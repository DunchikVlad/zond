package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
func (s *Server) sourceAudit(r *http.Request, action, name string, details map[string]any) {
	_ = s.st.AppendAudit(r.Context(), []audit.Event{{
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
	e, ok := s.openEditor(w)
	if !ok {
		return
	}
	entry := config.SourceEntry{
		Name:       r.FormValue("name"),
		Type:       r.FormValue("type"),
		DSN:        r.FormValue("dsn"),
		URI:        r.FormValue("uri"),
		Schedule:   r.FormValue("schedule"),
		ScanWindow: r.FormValue("scan_window"),
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
	raw, err := e.Bytes()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeBackupAndFile(s.connsPath, raw); err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	msg := "Источник " + entry.Name + " сохранён"
	if s.applyConns != nil {
		if _, err := s.applyConns(entry); err != nil {
			msg = "Файл записан, но применение не удалось (вступит после рестарта): " + err.Error()
		}
	}
	s.sourceAudit(r, action, entry.Name, map[string]any{
		"type": entry.Type, "schedule": entry.Schedule, "scan_window": entry.ScanWindow,
	})
	s.redirectSources(w, r, msg)
}

// handleSourceDelete — удаление источника (подтверждение — hx-confirm).
func (s *Server) handleSourceDelete(w http.ResponseWriter, r *http.Request) {
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
	raw, err := e.Bytes()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeBackupAndFile(s.connsPath, raw); err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.applyConns != nil {
		if _, err := s.applyConns(config.SourceEntry{Name: name}); err != nil {
			name += " (применение не удалось — после рестарта)"
		}
	}
	s.sourceAudit(r, "source_delete", name, map[string]any{})
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
	fmt.Fprintf(w, `<span class="ev">%s: %s</span>`, entry.Name, result)
}

func (s *Server) redirectSources(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/sources?msg="+url.QueryEscape(msg), http.StatusSeeOther)
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, mode); err != nil {
		return fmt.Errorf("запись %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("замена %s: %w", path, err)
	}
	return nil
}
