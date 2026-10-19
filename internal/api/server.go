// Package api — REST API v1 поверх Verdict Store (blueprint п. 11.2): список
// и карточки сканов, фильтрованные вердикты, ручное ревью, дрейф, экономика,
// экспорт CSV/JSON, health/ready. Единый конверт ошибок
// {error:{code,message,details}}; каждый запрос получает correlation id
// (X-Request-ID); мутации и экспорт аудируются (п. 14.2, fail-closed).
//
// Аутентификация — инкремент 5в (SSO SAML 2.0, ADR-0011); до неё actor =
// "api" и сервер по умолчанию слушает только loopback (ADR-impl-5б).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/logging"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Коды ошибок API (blueprint п. 11.2).
const (
	CodeInvalidRequest    = "invalid_request"
	CodeSourceUnavailable = "source_unavailable"
	CodeScanNotFound      = "scan_not_found"
	CodeReviewConflict    = "review_conflict"
	CodeInternal          = "internal"
)

// Actor — автор аудит-событий до появления SSO (п. 14.2; инкремент 5в
// заменит на sso:<subject>/token:<id>).
const Actor = "api"

// ScanRunner — запуск и мягкая остановка асинхронных прогонов
// (POST /api/v1/scans, POST /api/v1/scans/{id}/stop). Реализация —
// runner поверх scanengine (serve); в тестах — fake.
type ScanRunner interface {
	// Start запускает прогон в фоне и возвращает scan_id сразу.
	Start(source, profile string) (string, error)
	// Stop мягко останавливает прогон (ctx-отмена; статус interrupted).
	Stop(scanID string) error
}

// Server — HTTP-сервер REST API v1.
type Server struct {
	st      *store.Store
	log     *slog.Logger
	runner  ScanRunner // nil → POST /scans и stop → 501
	nowFn   func() time.Time
	maxRows int // export_max_rows (п. 11.2, default 50 000)
	mux     *http.ServeMux
}

// Option — настройка сервера.
type Option func(*Server)

// WithRunner подключает запуск сканов (serve-режим).
func WithRunner(r ScanRunner) Option { return func(s *Server) { s.runner = r } }

// WithExportMaxRows задаёт лимит строк экспорта (п. 11.2).
func WithExportMaxRows(n int) Option {
	return func(s *Server) {
		if n > 0 {
			s.maxRows = n
		}
	}
}

// New собирает сервер поверх store; log nil → discard.
func New(st *store.Store, log *slog.Logger, opts ...Option) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{st: st, log: log, nowFn: time.Now, maxRows: 50_000}
	for _, o := range opts {
		o(s)
	}
	s.routes()
	return s
}

// Handler возвращает корневой http.Handler (middleware: correlation id +
// access-лог). Используется и serve, и httptest.
func (s *Server) Handler() http.Handler {
	return s.withCorrelation(s.mux)
}

func (s *Server) routes() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/ready", s.handleReady)

	mux.HandleFunc("POST /api/v1/scans", s.handleScanStart)
	mux.HandleFunc("GET /api/v1/scans", s.handleScanList)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.handleScanGet)
	mux.HandleFunc("POST /api/v1/scans/{id}/stop", s.handleScanStop)

	mux.HandleFunc("GET /api/v1/verdicts", s.handleVerdictList)
	mux.HandleFunc("GET /api/v1/verdicts/{id}", s.handleVerdictGet)
	mux.HandleFunc("POST /api/v1/verdicts/{id}/review", s.handleReview)

	mux.HandleFunc("GET /api/v1/drift", s.handleDrift)
	mux.HandleFunc("GET /api/v1/stats/cost", s.handleCost)
	mux.HandleFunc("GET /api/v1/export", s.handleExport)
	s.mux = mux
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

// withCorrelation — correlation id на запрос (blueprint п. 14.1, п. 11.2):
// входящий X-Request-ID принимается, иначе генерируется; id кладётся в ctx
// (логгер добавляет correlation_id) и возвращается в ответе.
func (s *Server) withCorrelation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cid := r.Header.Get("X-Request-ID")
		if cid == "" {
			var b [16]byte
			_, _ = rand.Read(b[:])
			cid = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-ID", cid)
		ctx := logging.WithCorrelation(r.Context(), cid)
		start := s.nowFn()
		rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r.WithContext(ctx))
		s.log.InfoContext(ctx, "http", "method", r.Method, "path", r.URL.Path,
			"status", rw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// ---------------------------------------------------------------------------
// конверт ошибок и ответы (blueprint п. 11.2)
// ---------------------------------------------------------------------------

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

// writeError — единый конверт ошибок {error:{code,message,details}} (п. 11.2).
func writeError(w http.ResponseWriter, status int, code, message string, details any) {
	writeJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: message, Details: details}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// auditEvent пишет событие в аудит-лог; ошибка — fail-closed вызывающему
// (п. 14.2: действие без аудита не считается совершённым).
func (s *Server) auditEvent(ctx context.Context, category, action, target string, details map[string]any) error {
	return s.st.AppendAudit(ctx, []audit.Event{{
		Actor: Actor, Category: category, Action: action, Target: target,
		Details: details, TS: s.nowFn().UTC(),
	}})
}
