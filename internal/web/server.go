// Package web — веб-UI (инкремент 5г, blueprint п. 11.3, ADR-0007):
// server-rendered html/template + HTMX (vendored, без CDN), статика в embed.FS.
// UI работает поверх того же слоя store, что REST API (один контракт данных,
// ADR-impl-5г); аутентификация — SSO-сессии (cookie zond_session), RBAC
// п. 11.3 (viewer — просмотр). Заголовки п. 14: CSP default-src 'self',
// nosniff, no-referrer; пользовательский контент — только через экранирование
// html/template (safeHTML не используется).
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/observe"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/drift"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// ScanRunner — запуск/мягкая остановка прогонов из UI (тот же контракт, что
// api.ScanRunner; serve передаёт engineRunner).
type ScanRunner interface {
	Start(source, profile, actor string) (string, error)
	Resume(scanID, actor string) (string, error)
	Stop(scanID string) error
}

// Server — веб-UI поверх Verdict Store.
type Server struct {
	st          *store.Store
	log         *slog.Logger
	sessions    *auth.SessionStore
	authEnabled bool
	runner      ScanRunner
	cfg         *config.Bundle
	tmpl        *template.Template
	nowFn       func() time.Time

	// Инкремент S8-7: управление источниками из UI. conns — горячий
	// провайдер connections (заменяется serve после правки файла); connsPath
	// — редактируемый connections.yaml; applyConns — запись файла и
	// применение к процессу (atomic swap + scheduler), возвращает новый
	// разобранный конфиг. В тестах все три nil — используется s.cfg.
	conns      func() *config.Connections
	connsPath  string
	applyConns func(entry config.SourceEntry) (*config.Connections, error)
	sourceMu   sync.Mutex

	// Инкремент S8-8 (ADR-0014): горячая перезагрузка detectors.yaml через
	// /settings: bundle — текущий bundle; detectorsPath — редактируемый файл;
	// applyDetectors — перечитать и применить (пороги/веса/лимиты новых прогонов).
	bundle         func() *config.Bundle
	detectorsPath  string
	applyDetectors func() (*config.Detectors, error)
}

// Option — настройка Server (S8-7: провайдеры конфигурации для /sources).
type Option func(*Server)

// WithConns — горячий провайдер connections (после правки файла из UI).
func WithConns(fn func() *config.Connections) Option {
	return func(s *Server) { s.conns = fn }
}

// WithConnsPath — путь к редактируемому connections.yaml.
func WithConnsPath(path string) Option {
	return func(s *Server) { s.connsPath = path }
}

// WithApplyConns — перечитать уже записанный файл, сменить atomic-провайдер
// и перестроить расписания scheduler'а. Ошибка означает, что новое состояние
// не применено; /sources откатывает файл. Повторный вызов восстанавливает runtime.
func WithApplyConns(fn func(entry config.SourceEntry) (*config.Connections, error)) Option {
	return func(s *Server) { s.applyConns = fn }
}

// WithBundle — горячий провайдер bundle (S8-8, ADR-0014: свежие детекторы
// для /settings после правки файла).
func WithBundle(fn func() *config.Bundle) Option {
	return func(s *Server) { s.bundle = fn }
}

// WithDetectorsPath — путь к редактируемому detectors.yaml.
func WithDetectorsPath(path string) Option {
	return func(s *Server) { s.detectorsPath = path }
}

// WithApplyDetectors — колбэк «применить detectors.yaml без рестарта».
func WithApplyDetectors(fn func() (*config.Detectors, error)) Option {
	return func(s *Server) { s.applyDetectors = fn }
}

// bundleCurrent — текущий bundle: горячий провайдер или стартовый cfg.
func (s *Server) bundleCurrent() *config.Bundle {
	if s.bundle != nil {
		if b := s.bundle(); b != nil {
			return b
		}
	}
	return s.cfg
}

// connsCurrent — текущий connections: горячий провайдер или стартовый cfg.
func (s *Server) connsCurrent() *config.Connections {
	if s.conns != nil {
		if c := s.conns(); c != nil {
			return c
		}
	}
	return s.cfg.Connections
}

// New собирает UI. cfg — загруженный конфиг (источники/агенты/таксономия для
// /settings и форм). runner nil → старт/стоп недоступны (501).
func New(st *store.Store, log *slog.Logger, sessions *auth.SessionStore, authEnabled bool, runner ScanRunner, cfg *config.Bundle, opts ...Option) (*Server, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"fmtTime": fmtTime,
		"fmtTimeP": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return fmtTime(*t)
		},
		"pct":  func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"usd":  func(f float64) string { return fmt.Sprintf("$%.4f", f) },
		"conf": func(f float64) string { return fmt.Sprintf("%.2f", f) },
		"add":  func(a, b int) int { return a + b },
		"sub":  func(a, b int) int { return a - b },
		// evlines — строки evidence для детализации вердикта (S8-6).
		"evlines": evidenceLines,
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: шаблоны: %w", err)
	}
	srv := &Server{st: st, log: log, sessions: sessions, authEnabled: authEnabled,
		runner: runner, cfg: cfg, tmpl: tmpl, nowFn: time.Now}
	for _, opt := range opts {
		opt(srv)
	}
	return srv, nil
}

// Handler — корневой handler (middleware: security-заголовки → auth → mux).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /scans", s.handleScans)
	mux.HandleFunc("POST /scans/start", s.requireRole(auth.ActionScan, s.handleScanStart))
	mux.HandleFunc("POST /scans/{id}/stop", s.requireRole(auth.ActionScan, s.handleScanStop))
	mux.HandleFunc("POST /scans/{id}/resume", s.requireRole(auth.ActionScan, s.handleScanResume))
	mux.HandleFunc("GET /scans/{id}", s.handleScanDetail)
	mux.HandleFunc("GET /verdicts", s.handleVerdicts)
	mux.HandleFunc("GET /verdicts/{id}/calls", s.handleVerdictCalls) // S9-2: фрагмент вызовов LLM
	mux.HandleFunc("GET /review", s.handleReview)
	mux.HandleFunc("POST /review/{id}/action", s.requireRole(auth.ActionReview, s.handleReviewAction))
	mux.HandleFunc("POST /review/bulk", s.requireRole(auth.ActionReview, s.handleReviewBulk))
	mux.HandleFunc("GET /drift", s.handleDrift)
	mux.HandleFunc("GET /cost", s.handleCost)
	mux.HandleFunc("GET /alerts", s.handleAlerts)
	mux.HandleFunc("GET /audit", s.requireRole(auth.ActionAudit, s.handleAudit))
	mux.HandleFunc("GET /settings", s.handleSettings)
	// S8-7: управление источниками и расписаниями пересканов (только admin).
	mux.HandleFunc("GET /sources", s.requireRole(auth.ActionManage, s.handleSources))
	mux.HandleFunc("POST /sources/save", s.requireRole(auth.ActionManage, s.handleSourceSave))
	mux.HandleFunc("POST /sources/{name}/delete", s.requireRole(auth.ActionManage, s.handleSourceDelete))
	mux.HandleFunc("POST /sources/test", s.requireRole(auth.ActionManage, s.handleSourceTest))
	// S8-8: горячая правка detectors.yaml (ADR-0014), только admin.
	mux.HandleFunc("POST /settings/detectors/save", s.requireRole(auth.ActionManage, s.handleDetectorsSave))
	return s.withAuth(s.withCSRF(s.withSecurity(mux)))
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

// withSecurity — security-заголовки п. 14 (CSP default-src 'self', nosniff,
// no-referrer).
func (s *Server) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// CSRF double-submit (blueprint п. 14: CSRF-токены во всех HTMX-мутациях):
// cookie zond_csrf (не HttpOnly — читает JS-инициализация в _header.html)
// + обязательный заголовок X-CSRF-Token с тем же значением на любой
// не-GET-запрос. Классические HTML-формы (не HTMX) передают токен hidden-
// полем csrf_token — middleware принимает его как равнозначную пару
// (S8-6: форма запуска скана слала POST без заголовка и получала 403).
// Расхождение/отсутствие → 403. SameSite=Lax на cookie добавляет второй
// слой (cross-site POST не несёт cookie).
const (
	csrfCookie = "zond_csrf"
	csrfHeader = "X-CSRF-Token"
	csrfField  = "csrf_token"
)

// csrfCtxKey — свежесгенерированный токен middleware кладёт в контекст,
// чтобы рендереры могли вписать его в hidden-поле формы (в запросе его
// ещё нет — cookie выставляется ответом).
type csrfCtxKey struct{}

func (s *Server) withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if c, err := r.Cookie(csrfCookie); err == nil {
			tok = c.Value
		}
		if tok == "" {
			var b [32]byte
			_, _ = rand.Read(b[:])
			tok = hex.EncodeToString(b[:])
			http.SetCookie(w, &http.Cookie{
				Name: csrfCookie, Value: tok, Path: "/",
				SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
			})
			r = r.WithContext(context.WithValue(r.Context(), csrfCtxKey{}, tok))
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			sent := r.Header.Get(csrfHeader)
			if sent == "" {
				sent = r.FormValue(csrfField) // классическая форма (не HTMX)
			}
			if sent != tok || tok == "" {
				s.renderError(w, http.StatusForbidden, "CSRF-токен отсутствует или неверен — обновите страницу")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// csrfToken — токен для рендера форм: свежесгенерированный из контекста
// либо присланный клиентом cookie.
func (s *Server) csrfToken(r *http.Request) string {
	if v, ok := r.Context().Value(csrfCtxKey{}).(string); ok && v != "" {
		return v
	}
	if c, err := r.Cookie(csrfCookie); err == nil {
		return c.Value
	}
	return ""
}

// withAuth — субъект запроса: dev-режим (SSO выключен) → admin "dev";
// включён → cookie-сессия, иначе GET-страницы уходят на /saml/login (п. 11.3),
// POST → 403.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subj := auth.Subject{Actor: "dev", Role: auth.RoleAdmin}
		if s.authEnabled {
			// /saml/* в этом mux не обслуживается (serve отдаёт их API) —
			// но redirect на /saml/login не должен заворачиваться обратно
			// в auth (петля), поэтому пропускаем префикс как есть.
			if strings.HasPrefix(r.URL.Path, "/saml/") {
				next.ServeHTTP(w, r)
				return
			}
			subj = auth.Subject{}
			if c, err := r.Cookie(auth.SessionCookie); err == nil {
				if sess, ok := s.sessions.Get(c.Value); ok {
					subj = auth.Subject{Actor: "sso:" + sess.Subject, Role: sess.Role}
				}
			}
			if subj.Actor == "" {
				if r.Method == http.MethodGet {
					http.Redirect(w, r, "/saml/login", http.StatusFound)
					return
				}
				s.renderError(w, http.StatusForbidden, "требуется SSO-сессия")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(auth.WithSubject(r.Context(), subj)))
	})
}

// requireRole — RBAC для POST-действий (п. 11.3).
func (s *Server) requireRole(a auth.Action, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subj, _ := auth.SubjectFrom(r.Context())
		if !auth.Allows(subj.Role, a) {
			s.renderError(w, http.StatusForbidden, "недостаточно прав (требуется роль admin)")
			return
		}
		h(w, r)
	}
}

func (s *Server) subject(r *http.Request) auth.Subject {
	subj, _ := auth.SubjectFrom(r.Context())
	return subj
}

// ---------------------------------------------------------------------------
// рендер
// ---------------------------------------------------------------------------

type baseData struct {
	Subject auth.Subject
	Title   string
	Error   string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("web: рендер", "template", name, "error", err)
	}
}

func (s *Server) renderError(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "error.html", baseData{Title: "Ошибка", Error: msg})
}

// ---------------------------------------------------------------------------
// страницы
// ---------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.renderError(w, http.StatusNotFound, "страница не найдена")
		return
	}
	http.Redirect(w, r, "/scans", http.StatusFound)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scans, total, err := s.st.ListScans(ctx, store.ScanFilter{Limit: 200})
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type row struct {
		store.Scan
		Progress string
	}
	rows := make([]row, 0, len(scans))
	for _, sc := range scans {
		rows = append(rows, row{Scan: sc, Progress: scanProgress(sc.StatsJSON)})
	}
	sources := make([]string, 0, len(s.connsCurrent().Sources))
	for _, src := range s.connsCurrent().Sources {
		sources = append(sources, src.Name)
	}
	s.render(w, http.StatusOK, "scans.html", map[string]any{
		"Subject": s.subject(r), "Title": "Прогоны", "Scans": rows,
		"Total": total, "Sources": sources, "Runner": s.runner != nil,
		"CSRF": s.csrfToken(r), // hidden-поле формы запуска (S8-6)
	})
}

// scanProgress — "done/total" из stats_json прогона (п. 11.3 прогресс-бары).
func scanProgress(statsJSON string) string {
	var st struct {
		TablesTotal int `json:"tables_total"`
		TablesDone  int `json:"tables_done"`
	}
	_ = json.Unmarshal([]byte(statsJSON), &st)
	if st.TablesTotal == 0 {
		return "—"
	}
	return fmt.Sprintf("%d/%d", st.TablesDone, st.TablesTotal)
}

func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		s.renderError(w, http.StatusNotImplemented, "запуск сканов недоступен в этом режиме")
		return
	}
	source := r.FormValue("source")
	profile := r.FormValue("profile")
	actor := s.subject(r).Actor
	scanID, err := s.runner.Start(source, profile, actor)
	if err != nil {
		s.renderError(w, http.StatusBadGateway, "старт прогона: "+err.Error())
		return
	}
	s.log.Info("web: старт прогона", "scan_id", scanID, "actor", actor)
	http.Redirect(w, r, "/scans/"+scanID, http.StatusFound)
}

func (s *Server) handleScanResume(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		s.renderError(w, http.StatusNotImplemented, "продолжение недоступно")
		return
	}
	id := r.PathValue("id")
	newID, err := s.runner.Resume(id, s.subject(r).Actor)
	if err != nil {
		s.renderError(w, http.StatusConflict, "продолжение: "+err.Error())
		return
	}
	http.Redirect(w, r, "/scans/"+newID, http.StatusFound)
}

func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if s.runner == nil {
		s.renderError(w, http.StatusNotImplemented, "остановка недоступна")
		return
	}
	id := r.PathValue("id")
	if err := s.runner.Stop(id); err != nil {
		s.renderError(w, http.StatusConflict, "остановка: "+err.Error())
		return
	}
	http.Redirect(w, r, "/scans/"+id, http.StatusFound)
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	sc, err := s.st.GetScan(ctx, id)
	if err != nil {
		s.renderError(w, http.StatusNotFound, "прогон "+id+" не найден")
		return
	}
	tables, _ := s.st.ScanTables(ctx, id)
	sum, _ := s.st.VerdictSummary(ctx, id)
	cost, _ := s.st.ScanCostStats(ctx, id)
	failed, _ := s.st.FailedTables(ctx, id)
	if sum == nil {
		sum = &store.Summary{ByStatus: map[string]int{}, ByLabel: map[string]int{}, ByLayer: map[string]int{}}
	}
	s.render(w, http.StatusOK, "scan_detail.html", map[string]any{
		"Subject": s.subject(r), "Title": "Прогон " + id, "Scan": sc,
		"Tables": tables, "Summary": sum, "Cost": cost, "Errors": failed,
		"Runner": s.runner != nil, "CSRF": s.csrfToken(r),
	})
}

// knownLLMStatus — мягкая валидация фильтра llm_status (S9-2): неизвестное
// значение игнорируется (сторона store отфильтрует известное как есть).
func knownLLMStatus(s string) bool {
	switch verdict.LLMStatus(s) {
	case verdict.LLMStatusNotCalled, verdict.LLMStatusCalled, verdict.LLMStatusCacheHit,
		verdict.LLMStatusSmallSample, verdict.LLMStatusClusterPropagated,
		verdict.LLMStatusBudgetExceeded, verdict.LLMStatusError:
		return true
	}
	return false
}

func (s *Server) handleVerdicts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := store.VerdictFilter{
		ScanID:       r.URL.Query().Get("scan_id"),
		Label:        r.URL.Query().Get("label"),
		Sensitivity:  r.URL.Query().Get("sensitivity"),
		ReviewStatus: r.URL.Query().Get("review_status"),
		Table:        r.URL.Query().Get("table"),
		ClusterID:    r.URL.Query().Get("cluster_id"),
		RiskFirst:    r.URL.Query().Get("sort") != "scan",
		Limit:        50,
		Offset:       pageOffset(r.URL.Query().Get("page")),
	}
	if ls := r.URL.Query().Get("llm_status"); knownLLMStatus(ls) { // S9-2
		f.LLMStatus = ls
	}
	if mc := r.URL.Query().Get("min_conf"); mc != "" {
		f.MinConf, _ = strconv.ParseFloat(mc, 64)
	}
	vs, total, err := s.st.ListVerdictsFiltered(ctx, f)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, http.StatusOK, "verdicts.html", map[string]any{
		"Subject": s.subject(r), "Title": "Вердикты", "Verdicts": vs, "Total": total,
		"Filter": f, "Page": f.Offset/50 + 1, "Pages": (total + 49) / 50,
		"Labels": s.taxonomyLabels(),
	})
}

// handleVerdictCalls — GET /verdicts/{id}/calls: фрагмент со списком вызовов
// LLM вердикта (S9-2, HTMX: подгружается один раз по раскрытию деталей).
func (s *Server) handleVerdictCalls(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.st.GetVerdict(r.Context(), id); err != nil {
		s.renderError(w, http.StatusNotFound, "вердикт "+id+" не найден")
		return
	}
	calls, err := s.st.ListAgentCallsByVerdict(r.Context(), id)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.render(w, http.StatusOK, "verdict_calls.html", map[string]any{"Calls": calls})
}

func pageOffset(page string) int {
	p, _ := strconv.Atoi(page)
	if p <= 0 {
		return 0
	}
	return (p - 1) * 50
}

// fmtTime — локальное представление метки для UI.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func (s *Server) taxonomyLabels() []string {
	out := make([]string, 0, len(s.cfg.Taxonomy.Labels))
	for _, l := range s.cfg.Taxonomy.Labels {
		out = append(out, l.Name)
	}
	return out
}

// evidenceLines — безопасное строковое представление evidence карточки
// ревью: только известные ключи и статистика (ADR-0010: значения уже
// маскированы по построению; сырых значений в evidence нет по дизайну).
// S8-6: человекочитаемый рендер правил, примеров сэмпла и объяснений LLM
// (reason_ru вердикта и верификатора теперь хранятся в evidence движком).
func evidenceLines(v verdict.Verdict) []string {
	var lines []string
	add := func(k, val string) { lines = append(lines, k+": "+val) }
	if hit, ok := v.Evidence["cluster_propagated"]; ok && hit == true {
		add("кластер", "вердикт распространён от представителя кластера (п. 7.6)")
	}
	if hit, ok := v.Evidence["budget_exceeded"]; ok && hit == true {
		add("бюджет", "LLM не вызывался — исчерпан cost_scan_limit_usd (п. 10.4)")
	}
	if reason, ok := v.Evidence["reason"].(string); ok {
		add("причина", reason)
	}
	if lc, ok := v.Evidence["llm_cache"].(map[string]any); ok {
		if lc["hit"] == true {
			add("кэш LLM", "вердикт из кэша (п. 10.5); объяснение — из записи кэша (S9-2)")
		}
	}
	if llm, ok := v.Evidence["llm"].(map[string]any); ok {
		// S9-2: ответ агента и экономика вызова — полный per-column evidence.
		line := fmt.Sprintf("%v: %v", llm["model"], llm["label"])
		if c, ok := llm["confidence"].(float64); ok {
			line += fmt.Sprintf(" (conf %.2f", c)
			if s, ok := llm["sensitivity"].(string); ok && s != "" {
				line += ", " + s
			}
			line += ")"
		}
		if r, ok := llm["reason_ru"].(string); ok && r != "" {
			line += ": " + r
		}
		line += llmEconomy(llm)
		add("LLM", line)
	}
	if lv, ok := v.Evidence["llm_verify"].(map[string]any); ok {
		// S9-2: верификатор — с идентичностью агента и экономикой вызова.
		line := fmt.Sprintf("%v %v (conf %v): %v", lv["verdict"], lv["label"], lv["confidence"], lv["reason_ru"])
		if m, ok := lv["model"].(string); ok && m != "" {
			line += fmt.Sprintf(" · %v/%v, промпт v%v", lv["agent"], m, lv["prompt_version"])
		}
		line += llmEconomy(lv)
		add("верификатор", line)
	}
	if sample, ok := v.Evidence["sample"].(map[string]any); ok {
		line := fmt.Sprintf("значений %v, null %v из %v",
			sample["values"], sample["nulls"], sample["total"])
		if ex, ok := sample["examples"].([]any); ok && len(ex) > 0 {
			parts := make([]string, 0, len(ex))
			for _, e := range ex {
				if s, ok := e.(string); ok {
					parts = append(parts, strconv.Quote(truncate(s, 40)))
				}
			}
			if len(parts) > 0 {
				line += " · примеры: " + strings.Join(parts, ", ")
			}
		}
		add("сэмпл", line)
	}
	if rules, ok := v.Evidence["rules"].(map[string]any); ok && len(rules) > 0 {
		keys := make([]string, 0, len(rules))
		for k := range rules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			m, _ := rules[k].(map[string]any)
			p := fmt.Sprintf("%v %v/%v", k, m["matched"], m["total"])
			if m["checksum"] == true {
				p += " (checksum)"
			}
			parts = append(parts, p)
		}
		add("правила", strings.Join(parts, "; "))
	}
	return lines
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// llmEconomy — хвост строки evidence с экономикой вызова (S9-2):
// «· N/M токенов, $X, латентность Y мс, промпт vZ»; пустые/нулевые поля
// (кэш-записи, ошибки) пропускаются.
func llmEconomy(m map[string]any) string {
	var parts []string
	if ti, ok := m["tokens_in"].(float64); ok && ti > 0 {
		to, _ := m["tokens_out"].(float64)
		parts = append(parts, fmt.Sprintf("%.0f/%.0f токенов", ti, to))
	}
	if c, ok := m["cost_usd"].(float64); ok && c > 0 {
		parts = append(parts, fmt.Sprintf("$%.4f", c))
	}
	if l, ok := m["latency_ms"].(float64); ok && l > 0 {
		parts = append(parts, fmt.Sprintf("латентность %.0f мс", l))
	}
	if p, ok := m["prompt_version"].(string); ok && p != "" {
		parts = append(parts, "промпт v"+p)
	}
	if len(parts) == 0 {
		return ""
	}
	return " · " + strings.Join(parts, ", ")
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	s.renderReviewQueue(w, r, http.StatusOK, "")
}

func (s *Server) handleReviewAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	action := store.ReviewAction(r.FormValue("action"))
	label := r.FormValue("label")
	if _, err := s.st.ApplyReview(r.Context(), id, action, verdict.Label(label), s.subject(r).Actor, s.nowFn()); err != nil {
		var rc *store.ReviewConflict
		if errors.As(err, &rc) {
			s.renderReviewQueue(w, r, http.StatusOK, "Конфликт по "+id+": "+rc.Reason)
			return
		}
		s.renderReviewQueue(w, r, http.StatusOK, "Ошибка по "+id+": "+err.Error())
		return
	}
	s.renderReviewQueue(w, r, http.StatusOK, "")
}

func (s *Server) handleReviewBulk(w http.ResponseWriter, r *http.Request) {
	action := store.ReviewAction(r.FormValue("action"))
	ids := r.Form["ids"]
	var done, failed int
	var lastErr string
	for _, id := range ids {
		if _, err := s.st.ApplyReview(r.Context(), id, action, "", s.subject(r).Actor, s.nowFn()); err != nil {
			failed++
			lastErr = err.Error()
		} else {
			done++
		}
	}
	msg := fmt.Sprintf("Bulk %s: выполнено %d, отказов %d", action, done, failed)
	if failed > 0 {
		msg += " (последняя ошибка: " + truncate(lastErr, 120) + ")"
	}
	s.renderReviewQueue(w, r, http.StatusOK, msg)
}

// renderReviewQueue — страница /review или HTMX-фрагмент очереди после
// действия (п. 11.3: карточки с маскированными примерами и reason_ru).
func (s *Server) renderReviewQueue(w http.ResponseWriter, r *http.Request, status int, msg string) {
	ctx := r.Context()
	vs, total, err := s.st.ListVerdictsFiltered(ctx, store.VerdictFilter{
		ReviewStatus: "pending", RiskFirst: true, Limit: 50,
	})
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type card struct {
		V             verdict.Verdict
		EvidenceLines []string
	}
	cards := make([]card, 0, len(vs))
	for _, v := range vs {
		cards = append(cards, card{V: v, EvidenceLines: evidenceLines(v)})
	}
	data := map[string]any{
		"Subject": s.subject(r), "Title": "Ревью", "Queue": cards,
		"Total": total, "Msg": msg, "Labels": s.taxonomyLabels(),
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, status, "review_queue.html", data)
		return
	}
	s.render(w, status, "review.html", data)
}

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sources := make([]string, 0, len(s.connsCurrent().Sources))
	for _, src := range s.connsCurrent().Sources {
		sources = append(sources, src.Name)
	}
	source := r.URL.Query().Get("source")
	var rep *drift.Report
	var ok bool
	var err error
	if source != "" {
		rep, ok, err = drift.BetweenLatest(ctx, s.st, source, nil)
		if err != nil {
			s.renderError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.render(w, http.StatusOK, "drift.html", map[string]any{
		"Subject": s.subject(r), "Title": "Дрейф схемы", "Sources": sources,
		"Source": source, "Report": rep, "OK": ok,
	})
}

func (s *Server) handleCost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scans, _, _ := s.st.ListScans(ctx, store.ScanFilter{Limit: 100})
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" && len(scans) > 0 {
		scanID = scans[0].ID
	}
	var stats *store.CostStats
	if scanID != "" {
		stats, _ = s.st.ScanCostStats(ctx, scanID)
	}
	// Инстанс-wide блок (п. 17): экономика/латентность/ревью за окно.
	instance, _ := observe.BuildSnapshot(ctx, s.st, observe.Default, observe.DefaultWindow)
	s.render(w, http.StatusOK, "cost.html", map[string]any{
		"Subject": s.subject(r), "Title": "Экономика", "Scans": scans,
		"ScanID": scanID, "Stats": stats, "Instance": instance,
	})
}

// handleAlerts — журнал алертинга (S6в, п. 17): открытые и закрытые алерты
// с фильтром состояния (?state=open|resolved). Просмотр — роль viewer
// (операционная информация, как /cost).
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	alerts, err := s.st.AlertList(ctx, state, 500)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	open, _ := s.st.AlertOpenCount(ctx)
	s.render(w, http.StatusOK, "alerts.html", map[string]any{
		"Subject": s.subject(r), "Title": "Алерты",
		"Alerts": alerts, "Open": open, "State": state,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	since := q.Get("since")
	f := audit.Filter{
		Actor:    q.Get("actor"),
		Category: q.Get("category"),
		ScanID:   q.Get("scan"),
		Limit:    500,
	}
	if since != "" {
		if t, err := time.ParseInLocation("2006-01-02", since, time.Local); err == nil {
			f.Since = &t
		}
	}
	entries, err := s.st.AuditList(ctx, f)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ver, _ := s.st.AuditVerify(ctx)
	s.render(w, http.StatusOK, "audit.html", map[string]any{
		"Subject": s.subject(r), "Title": "Аудит", "Entries": entries,
		"Filter": f, "Since": since, "Verify": ver,
	})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	// Sources показываем без DSN/URI (в памяти после интерполяции секретов —
	// не выводим, п. 14.1/ADR-0010).
	type srcView struct {
		Name, Type string
	}
	srcs := make([]srcView, 0, len(s.connsCurrent().Sources))
	for _, src := range s.connsCurrent().Sources {
		srcs = append(srcs, srcView{Name: src.Name, Type: src.Type})
	}
	b := s.bundleCurrent()
	// S8-8: редактируемые скаляры detectors — из raw-файла (без сюрпризов
	// интерполяции); при недоступности редактора — из загруженного bundle.
	detView := config.DetectorsView{
		Profile: b.Detectors.Scan.Profile, TauAccept: b.Detectors.Ensemble.TauAccept,
		TauReview: b.Detectors.Ensemble.TauReview,
		WMeta:     b.Detectors.Ensemble.Weights["meta"], WRules: b.Detectors.Ensemble.Weights["rules"],
		WLLM:       b.Detectors.Ensemble.Weights["llm"],
		Similarity: b.Detectors.Cluster.Similarity, MaxSize: b.Detectors.Cluster.MaxSize,
		MaxConcurrent: b.Detectors.Proxy.MaxConcurrent, RateLimitRPS: b.Detectors.Proxy.RateLimitRPS,
		CostScanLimitUSD: b.Detectors.Proxy.CostScanLimitUSD, Offline: b.Detectors.Proxy.Offline,
	}
	if s.detectorsPath != "" {
		if de, err := config.OpenDetectorsEditor(s.detectorsPath); err == nil {
			if v, err := de.View(); err == nil {
				detView = v
			}
		}
	}
	s.render(w, http.StatusOK, "settings.html", map[string]any{
		"Subject":  s.subject(r),
		"Title":    "Настройки",
		"Sources":  srcs,
		"Agents":   b.Detectors.Agents,
		"Taxonomy": s.cfg.Taxonomy,
		"Ensemble": b.Detectors.Ensemble,
		"Det":      detView,
		"CSRF":     s.csrfToken(r),
		"Msg":      r.URL.Query().Get("msg"),
	})
}
