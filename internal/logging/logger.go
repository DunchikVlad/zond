// Package logging — операционные JSON-логи (ADR-0013, blueprint п. 14.1):
// уровни, correlation id, обязательный redact перед записью
// (SecretRedactor — redactor.go; инкремент S7г).
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
// Необязательные redactors применяются к сообщению и строковым атрибутам
// перед записью (п. 14.1 — обязательный redact; без них — без маскирования).
func New(w io.Writer, level string, redactors ...Redactor) *slog.Logger {
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
	var h slog.Handler = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})
	if len(redactors) > 0 {
		h = redactHandler{next: h, rs: redactors}
	}
	return slog.New(correlationHandler{next: h})
}

// redactHandler — slog.Handler-обёртка: маскирует сообщение и строковые
// атрибуты записи всеми redactors (п. 14.1: единая точка перед записью).
type redactHandler struct {
	next slog.Handler
	rs   []Redactor
}

func (h redactHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.redact(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		if a.Value.Kind() == slog.KindString {
			a.Value = slog.StringValue(h.redact(a.Value.String()))
		}
		out.AddAttrs(a)
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h redactHandler) redact(s string) string {
	for _, r := range h.rs {
		s = r.Redact(s)
	}
	return s
}

func (h redactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return redactHandler{next: h.next.WithAttrs(attrs), rs: h.rs}
}

func (h redactHandler) WithGroup(name string) slog.Handler {
	return redactHandler{next: h.next.WithGroup(name), rs: h.rs}
}
