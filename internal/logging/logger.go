// Package logging — операционные JSON-логи (ADR-0013, blueprint п. 14.1):
// уровни, correlation id, обязательный redact перед записью.
// Redact-реализация прибывает с этапом Agent Proxy; контракт — сейчас.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

type correlationKey struct{}

// WithCorrelation возвращает ctx с correlation id (blueprint п. 14.1).
func WithCorrelation(ctx context.Context, cid string) context.Context {
	return context.WithValue(ctx, correlationKey{}, cid)
}

// Correlation извлекает correlation id из ctx.
func Correlation(ctx context.Context) string {
	cid, _ := ctx.Value(correlationKey{}).(string)
	return cid
}

// Redactor маскирует чувствительные значения перед записью в лог
// (blueprint п. 14.1: секреты, PII, тела LLM-запросов). Этап 0: NoopRedactor.
type Redactor interface {
	Redact(s string) string
}

// NoopRedactor не изменяет строки (заглушка до этапа Agent Proxy).
type NoopRedactor struct{}

// Redact возвращает строку без изменений.
func (NoopRedactor) Redact(s string) string { return s }

type correlationHandler struct {
	next slog.Handler
}

func (h correlationHandler) Handle(ctx context.Context, r slog.Record) error {
	if cid := Correlation(ctx); cid != "" {
		r.AddAttrs(slog.String("correlation_id", cid))
	}
	return h.next.Handle(ctx, r)
}

func (h correlationHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h correlationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return correlationHandler{next: h.next.WithAttrs(attrs)}
}

func (h correlationHandler) WithGroup(name string) slog.Handler {
	return correlationHandler{next: h.next.WithGroup(name)}
}

// New — JSON-логгер в w. level: debug|info|warn|error (по умолчанию info).
func New(w io.Writer, level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
	return slog.New(correlationHandler{next: base})
}
