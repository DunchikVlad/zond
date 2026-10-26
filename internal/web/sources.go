package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
)

// ---------------------------------------------------------------------------
// S8-7: управление источниками и расписаниями пересканов из UI (только admin).
// Правка идёт в connections.yaml через config.SourceEditor (yaml.Node — без
// потери комментариев и ${ENV}-литералов), применение — горячее, без рестарта
// (колбэк serve: перечитать конфиг, atomic swap, scheduler.ReplaceSources).
// ---------------------------------------------------------------------------

// sourceAudit — событие изменения источника в hash-chain (п. 14.2), actor —
// субъект запроса; секретов в деталях нет (dsn/uri не логируются).
func (s *Server) sourceAudit(r *http.Request, action, name string, details map[string]any) error {
	return s.st.AppendAudit(r.Context(), []audit.Event{{
		Actor: s.subject(r).Actor, Category: audit.CatAdmin, Action: action,
		Target: "source:" + name, Details: details, TS: s.nowFn(),
	}})
}

func (s *Server) openEditor(w http.ResponseWriter) (*config.SourceEditor, bool) {
	if s.connsPath == "" {
		s.renderError(w, http.StatusInternalServerError, "путь к connections.yaml не настроен (WithConnsPath)")
		return nil, false
	}
	e, err := config.OpenSourceEditor(s.connsPath)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	return e, true
}

// handleSources — список источников с формами правки.
func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	e, ok := s.openEditor(w)
	if !ok {
		return
	}
	entries, err := e.Sources()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, http.StatusOK, "sources.html", map[string]any{
		"Subject": s.subject(r), "Title": "Источники",
		"Sources": entries, "CSRF": s.csrfToken(r), "Msg": r.URL.Query().Get("msg"),
	})
}

// handleSourceSave — добавление/обновление источника: валидация → запись
// файла (с бэкапом) → горячее применение → аудит.
func (s *Server) handleSourceSave(w http.ResponseWriter, r *http.Request) {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	e, ok := s.openEditor(w)
	if !ok {
		return
	}
	entry := config.SourceEntry{
		Name:       r.FormValue("name"),
		Type:       r.FormValue("type"),
		DSN:        r.FormValue("dsn"),
		URI:        r.FormValue("uri"),
		Ref:        r.FormValue("ref"),
		Schedule:   r.FormValue("schedule"),
		ScanWindow: r.FormValue("scan_window"),
	}
	limits := []*int{&entry.MaxConcurrentScans, &entry.MaxConcurrentTables, &entry.QueryTimeoutS}
	for i, key := range []string{"max_concurrent_scans", "max_concurrent_tables", "query_timeout_s"} {
		n, err := sourceFormInt(r, key)
		if err != nil {
			s.redirectSources(w, r, "Ошибка: "+err.Error())
			return
		}
		*limits[i] = n
	}
	if err := entry.Validate(); err != nil {
		s.redirectSources(w, r, "Ошибка: "+err.Error())
		return
	}
	existing, err := e.Sources()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	action := "source_add"
	for _, es := range existing {
		if es.Name == entry.Name {
			action = "source_update"
			break
		}
	}
	if err := e.Upsert(entry); err != nil {
		s.redirectSources(w, r, "Ошибка: "+err.Error())
		return
	}
	if err := e.ValidateAll(); err != nil {
		s.redirectSources(w, r, "Ошибка схемы файла: "+err.Error())
		return
	}
	details := map[string]any{
		"type": entry.Type, "schedule": entry.Schedule, "scan_window": entry.ScanWindow,
		"max_concurrent_scans": entry.MaxConcurrentScans, "max_concurrent_tables": entry.MaxConcurrentTables,
		"query_timeout_s": entry.QueryTimeoutS,
	}
	if err := s.commitSource(r, e, entry, action, entry.Name, details); err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.redirectSources(w, r, "Источник "+entry.Name+" сохранён")
}

// handleSourceDelete — удаление источника (подтверждение — hx-confirm).
func (s *Server) handleSourceDelete(w http.ResponseWriter, r *http.Request) {
	s.sourceMu.Lock()
	defer s.sourceMu.Unlock()
	name := r.PathValue("name")
	e, ok := s.openEditor(w)
	if !ok {
		return
	}
	if err := e.Delete(name); err != nil {
		s.redirectSources(w, r, "Ошибка: "+err.Error())
		return
	}
	if err := e.ValidateAll(); err != nil {
		s.redirectSources(w, r, "Ошибка схемы файла: "+err.Error())
		return
	}
	entry := config.SourceEntry{Name: name}
	if err := s.commitSource(r, e, entry, "source_delete", name, map[string]any{}); err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.redirectSources(w, r, "Источник "+name+" удалён")
}

// handleSourceTest — проверка подключения: resolve ${ENV} → коннектор → Ping.
// Отвечает HTMX-фрагментом (без навигации).
func (s *Server) handleSourceTest(w http.ResponseWriter, r *http.Request) {
	entry := config.SourceEntry{
		Name: r.FormValue("name"),
		Type: r.FormValue("type"),
		DSN:  r.FormValue("dsn"),
		URI:  r.FormValue("uri"),
	}
	connStr := entry.DSN
	if connStr == "" {
		connStr = entry.URI
	}
	connStr = config.ExpandEnv(connStr) // ${ENV} → значения из окружения процесса (п. 12)
	result := "OK"
	if strings.Contains(connStr, "${") {
		result = "Не заданы переменные окружения в строке подключения: " + connStr
	} else if err := entry.Validate(); err != nil {
		result = "Ошибка валидации: " + err.Error()
	} else if factory, ok := connector.Lookup(entry.Type); ok {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		conn, err := factory(connStr)
		if err != nil {
			result = "Конструктор: " + err.Error()
		} else {
			err = conn.Ping(ctx)
			conn.Close()
			if err != nil {
				result = "Ping: " + err.Error()
			}
		}
	} else {
		result = "Коннектор " + entry.Type + " не зарегистрирован"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<span class="ev">%s: %s</span>`, html.EscapeString(entry.Name), html.EscapeString(result))
}

func (s *Server) redirectSources(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/sources?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func sourceFormInt(r *http.Request, key string) (int, error) {
	raw := r.FormValue(key)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: ожидается целое число", key)
	}
	return n, nil
}

// commitSource выполняет изменение как сериализованную транзакцию с компенсацией:
// файл → hot apply → обязательный аудит. При ошибке восстанавливается старое состояние.
func (s *Server) commitSource(r *http.Request, e *config.SourceEditor, entry config.SourceEntry, action, name string, details map[string]any) error {
	raw, err := e.Bytes()
	if err != nil {
		return err
	}
	prev, err := os.ReadFile(s.connsPath)
	if err != nil {
		return fmt.Errorf("снимок %s: %w", s.connsPath, err)
	}
	if err := writeBackupAndFile(s.connsPath, raw); err != nil {
		return err
	}
	if s.applyConns != nil {
		if _, err := s.applyConns(entry); err != nil {
			rollbackErr := restoreSourceFile(s.connsPath, prev)
			return errors.Join(fmt.Errorf("применение источника отменено: %w", err), rollbackErr)
		}
	}
	if err := s.sourceAudit(r, action, name, details); err != nil {
		rollbackErr := restoreSourceFile(s.connsPath, prev)
		var applyErr error
		if s.applyConns != nil {
			_, applyErr = s.applyConns(entry)
		}
		return errors.Join(fmt.Errorf("аудит источника; изменение отменено: %w", err), rollbackErr, applyErr)
	}
	return nil
}

func restoreSourceFile(path string, raw []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(path, raw, mode); err != nil {
		return fmt.Errorf("откат %s: %w", path, err)
	}
	return nil
}

// writeBackupAndFile — атомарная замена файла с бэкапом .bak (S8-7).
func writeBackupAndFile(path string, raw []byte) error {
	prev, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("чтение %s для бэкапа: %w", path, err)
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(path+".bak", prev, mode); err != nil {
		return fmt.Errorf("бэкап %s.bak: %w", path, err)
	}
	return writeFileAtomic(path, raw, mode)
}

func writeFileAtomic(path string, raw []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("временный файл %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("права %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("запись %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("закрытие %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("замена %s: %w", path, err)
	}
	return nil
}

// handleDetectorsSave — S8-8 (ADR-0014): сохранение порогов/весов/лимитов
// detectors.yaml через UI с горячим применением (только admin).
func (s *Server) handleDetectorsSave(w http.ResponseWriter, r *http.Request) {
	if s.detectorsPath == "" {
		s.renderError(w, http.StatusInternalServerError, "путь к detectors.yaml не настроен (WithDetectorsPath)")
		return
	}
	de, err := config.OpenDetectorsEditor(s.detectorsPath)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	v := config.DetectorsView{
		Profile:          r.FormValue("profile"),
		TauAccept:        parseFormFloat(r, "tau_accept"),
		TauReview:        parseFormFloat(r, "tau_review"),
		WMeta:            parseFormFloat(r, "w_meta"),
		WRules:           parseFormFloat(r, "w_rules"),
		WLLM:             parseFormFloat(r, "w_llm"),
		Similarity:       parseFormFloat(r, "similarity"),
		MaxSize:          parseFormInt(r, "max_size"),
		MaxConcurrent:    parseFormInt(r, "max_concurrent"),
		RateLimitRPS:     parseFormFloat(r, "rate_limit_rps"),
		CostScanLimitUSD: parseFormFloat(r, "cost_scan_limit_usd"),
		Offline:          r.FormValue("offline") == "on",
	}
	if err := de.Apply(v); err != nil {
		http.Redirect(w, r, "/settings?msg="+url.QueryEscape("Ошибка: "+err.Error()), http.StatusSeeOther)
		return
	}
	raw, err := de.Bytes()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeBackupAndFile(s.detectorsPath, raw); err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	msg := "Детекторы сохранены — применены к новым прогонам без рестарта"
	if s.applyDetectors != nil {
		if _, err := s.applyDetectors(); err != nil {
			msg = "Файл записан, применение не удалось (вступит после рестарта): " + err.Error()
		}
	}
	s.sourceAudit(r, "detectors_update", "detectors", map[string]any{
		"profile": v.Profile, "tau_accept": v.TauAccept, "tau_review": v.TauReview,
	})
	http.Redirect(w, r, "/settings?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func parseFormFloat(r *http.Request, key string) float64 {
	f, _ := strconv.ParseFloat(r.FormValue(key), 64)
	return f
}

func parseFormInt(r *http.Request, key string) int {
	n, _ := strconv.Atoi(r.FormValue(key))
	return n
}
