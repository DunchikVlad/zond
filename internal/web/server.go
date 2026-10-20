// Package web — веб-UI (инкремент 5г, blueprint п. 11.3, ADR-0007):
// server-rendered html/template + HTMX (vendored, без CDN), статика в embed.FS.
// UI работает поверх того же слоя store, что REST API (один контракт данных,
// ADR-impl-5г); аутентификация — SSO-сессии (cookie zond_session), RBAC
// п. 11.3 (viewer — просмотр). Заголовки п. 14: CSP default-src 'self',
// nosniff, no-referrer; пользовательский контент — только через экранирование
// html/template (safeHTML не используется).
package web

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/config"
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
}

// New собирает UI. cfg — загруженный конфиг (источники/агенты/таксономия для
// /settings и форм). runner nil → старт/стоп недоступны (501).
func New(st *store.Store, log *slog.Logger, sessions *auth.SessionStore, authEnabled bool, runner ScanRunner, cfg *config.Bundle) (*Server, error) {
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
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: шаблоны: %w", err)
	}
	return &Server{st: st, log: log, sessions: sessions, authEnabled: authEnabled,
		runner: runner, cfg: cfg, tmpl: tmpl, nowFn: time.Now}, nil
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
	mux.HandleFunc("GET /scans/{id}", s.handleScanDetail)
	mux.HandleFunc("GET /verdicts", s.handleVerdicts)
	mux.HandleFunc("GET /review", s.handleReview)
	mux.HandleFunc("POST /review/{id}/action", s.requireRole(auth.ActionReview, s.handleReviewAction))
	mux.HandleFunc("POST /review/bulk", s.requireRole(auth.ActionReview, s.handleReviewBulk))
	mux.HandleFunc("GET /drift", s.handleDrift)
	mux.HandleFunc("GET /cost", s.handleCost)
	mux.HandleFunc("GET /audit", s.requireRole(auth.ActionAudit, s.handleAudit))
	mux.HandleFunc("GET /settings", s.handleSettings)
	return s.withAuth(s.withSecurity(mux))
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

func (s *Server) withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
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
	sources := make([]string, 0, len(s.cfg.Connections.Sources))
	for _, src := range s.cfg.Connections.Sources {
		sources = append(sources, src.Name)
	}
	s.render(w, http.StatusOK, "scans.html", map[string]any{
		"Subject": s.subject(r), "Title": "Прогоны", "Scans": rows,
		"Total": total, "Sources": sources, "Runner": s.runner != nil,
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
		"Runner": s.runner != nil,
	})
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
			add("кэш LLM", "вердикт из кэша (п. 10.5)")
		}
	}
	if sample, ok := v.Evidence["sample"].(map[string]any); ok {
		add("сэмпл", fmt.Sprintf("значений %v, null %v из %v",
			sample["values"], sample["nulls"], sample["total"]))
	}
	if rules, ok := v.Evidence["rules"].(map[string]any); ok && len(rules) > 0 {
		if b, err := json.Marshal(rules); err == nil {
			add("rules", truncate(string(b), 240))
		}
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
	sources := make([]string, 0, len(s.cfg.Connections.Sources))
	for _, src := range s.cfg.Connections.Sources {
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
	s.render(w, http.StatusOK, "cost.html", map[string]any{
		"Subject": s.subject(r), "Title": "Экономика", "Scans": scans,
		"ScanID": scanID, "Stats": stats,
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
	srcs := make([]srcView, 0, len(s.cfg.Connections.Sources))
	for _, src := range s.cfg.Connections.Sources {
		srcs = append(srcs, srcView{Name: src.Name, Type: src.Type})
	}
	s.render(w, http.StatusOK, "settings.html", map[string]any{
		"Subject":  s.subject(r),
		"Title":    "Настройки",
		"Sources":  srcs,
		"Agents":   s.cfg.Detectors.Agents,
		"Taxonomy": s.cfg.Taxonomy,
		"Ensemble": s.cfg.Detectors.Ensemble,
	})
}
