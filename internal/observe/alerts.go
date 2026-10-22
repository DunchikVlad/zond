// Встроенный алертинг (blueprint п. 17; события — в UI /alerts, audit-лог
// категории alert и опциональный webhook). Правила:
//
//   - budget_exceeded: последний прогон источника остановлен бюджетом
//     (п. 10.4), цель source:<name>;
//   - pending_backlog: в последнем прогоне источника pending больше порога
//     (R9, default 500 на источник), цель source:<name>;
//   - llm_unavailable: больше 5 ошибок LLM подряд (п. 17), цель agent:<id>;
//   - audit_chain_break: разрыв hash-chain аудита (п. 14.2, критично),
//     цель audit_log.
//
// Дедуп открытых алертов — (rule, target) в store; угасшие правила
// закрываются следующим прогоном. Актор событий — scheduler (п. 14.2:
// фоновые задачи журналируются).
package observe

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Имена правил и пороги (п. 17, R9).
const (
	RuleBudgetExceeded  = "budget_exceeded"
	RulePendingBacklog  = "pending_backlog"
	RuleLLMUnavailable  = "llm_unavailable"
	RuleAuditChainBreak = "audit_chain_break"

	// Severity-уровни.
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// DefaultPendingThreshold — порог R9: pending > 500 вердиктов на источник.
const DefaultPendingThreshold = 500

// actor — автор аудит-событий алертинга (п. 14.2: фоновые задачи).
const actor = "scheduler"

// Evaluator — оценщик правил алертинга; запускается по расписанию
// scheduler'а (default */5 мин).
type Evaluator struct {
	st               *store.Store
	log              *slog.Logger
	nowFn            func() time.Time
	pendingThreshold int
	webhook          *Webhook
}

// Option — настройка Evaluator (тесты).
type Option func(*Evaluator)

// WithPendingThreshold задаёт порог pending_backlog (R9; default 500).
func WithPendingThreshold(n int) Option {
	return func(e *Evaluator) {
		if n > 0 {
			e.pendingThreshold = n
		}
	}
}

// WithWebhook подключает внешнюю доставку событий алертов (п. 17).
func WithWebhook(w *Webhook) Option {
	return func(e *Evaluator) { e.webhook = w }
}

// WithNowFn подменяет часы (тесты).
func WithNowFn(fn func() time.Time) Option {
	return func(e *Evaluator) { e.nowFn = fn }
}

// NewEvaluator собирает оценщик; log nil → discard.
func NewEvaluator(st *store.Store, log *slog.Logger, opts ...Option) *Evaluator {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	e := &Evaluator{st: st, log: log, nowFn: time.Now, pendingThreshold: DefaultPendingThreshold}
	for _, o := range opts {
		o(e)
	}
	return e
}

// firing — активное срабатывание правила.
type firing struct {
	rule, severity, target, message string
	details                         map[string]any
}

// Eval — один проход: собрать активные срабатывания, поднять новые алерты,
// закрыть угасшие. Ошибки изолируются и пишутся в лог — алертинг не роняет
// расписание scheduler'а и не отключает остальные правила.
func (e *Evaluator) Eval(ctx context.Context) {
	fired := e.collect(ctx)
	active := map[string]bool{}
	for _, f := range fired {
		active[f.rule+":"+f.target] = true
		created, err := e.st.AlertRaise(ctx, f.rule, f.severity, f.target, f.message, f.details, e.nowFn())
		if err != nil {
			e.log.Error("alerts: подъём алерта", "rule", f.rule, "target", f.target, "error", err)
			continue
		}
		if created {
			e.log.Warn("alerts: новый алерт", "rule", f.rule, "severity", f.severity, "target", f.target)
			e.audit(ctx, "alert_raise", f)
			e.notify(ctx, "raised", f)
		}
	}
	resolved, err := e.st.AlertResolveNotIn(ctx, []string{
		RuleBudgetExceeded, RulePendingBacklog, RuleLLMUnavailable, RuleAuditChainBreak,
	}, active, e.nowFn())
	if err != nil {
		e.log.Error("alerts: закрытие алертов", "error", err)
		return
	}
	for _, a := range resolved {
		e.log.Info("alerts: алерт закрыт (правило перестало стрелять)",
			"rule", a.Rule, "target", a.Target)
		e.auditResolved(ctx, a)
		e.notifyResolved(ctx, a)
	}
}

// collect — оценка всех правил; паники правил не прорываются наружу
// (recover на уровне правила, ошибка — в лог).
func (e *Evaluator) collect(ctx context.Context) []firing {
	var out []firing
	collect := func(rule string, fn func() []firing) {
		defer func() {
			if r := recover(); r != nil {
				e.log.Error("alerts: паника в правиле", "rule", rule, "panic", r)
			}
		}()
		out = append(out, fn()...)
	}
	collect(RuleBudgetExceeded, func() []firing { return e.ruleBudget(ctx) })
	collect(RulePendingBacklog, func() []firing { return e.rulePending(ctx) })
	collect(RuleLLMUnavailable, func() []firing { return e.ruleLLMUnavailable(ctx) })
	collect(RuleAuditChainBreak, func() []firing { return e.ruleChain(ctx) })
	return out
}

func (e *Evaluator) ruleBudget(ctx context.Context) []firing {
	ov, err := e.st.LatestScanOverviews(ctx)
	if err != nil {
		e.log.Error("alerts: budget_exceeded", "error", err)
		return nil
	}
	var out []firing
	for _, o := range ov {
		if o.Status != "budget_exceeded" {
			continue
		}
		out = append(out, firing{
			rule: RuleBudgetExceeded, severity: SeverityWarning, target: "source:" + o.Source,
			message: fmt.Sprintf("прогон %s остановлен бюджетом: cost_scan_limit_usd исчерпан (п. 10.4)", o.ScanID),
			details: map[string]any{"scan_id": o.ScanID, "source": o.Source},
		})
	}
	return out
}

func (e *Evaluator) rulePending(ctx context.Context) []firing {
	ov, err := e.st.LatestScanOverviews(ctx)
	if err != nil {
		e.log.Error("alerts: pending_backlog", "error", err)
		return nil
	}
	var out []firing
	for _, o := range ov {
		if o.Pending <= e.pendingThreshold {
			continue
		}
		out = append(out, firing{
			rule: RulePendingBacklog, severity: SeverityWarning, target: "source:" + o.Source,
			message: fmt.Sprintf("очередь ревью источника %s: %d pending (> %d, R9)",
				o.Source, o.Pending, e.pendingThreshold),
			details: map[string]any{"source": o.Source, "pending": o.Pending, "threshold": e.pendingThreshold},
		})
	}
	return out
}

func (e *Evaluator) ruleLLMUnavailable(ctx context.Context) []firing {
	streak, agent, err := e.st.LLMErrorStreak(ctx, 6)
	if err != nil {
		e.log.Error("alerts: llm_unavailable", "error", err)
		return nil
	}
	if streak <= 5 {
		return nil
	}
	if agent == "" {
		agent = "unknown"
	}
	return []firing{{
		rule: RuleLLMUnavailable, severity: SeverityCritical, target: "agent:" + agent,
		message: fmt.Sprintf("LLM недоступен: %d ошибок вызовов подряд (агент %s)", streak, agent),
		details: map[string]any{"streak": streak, "agent": agent},
	}}
}

func (e *Evaluator) ruleChain(ctx context.Context) []firing {
	rep, err := e.st.AuditVerify(ctx)
	if err != nil {
		e.log.Error("alerts: audit_chain_break", "error", err)
		return nil
	}
	if rep.OK() {
		return nil
	}
	return []firing{{
		rule: RuleAuditChainBreak, severity: SeverityCritical, target: "audit_log",
		message: fmt.Sprintf("разрыв hash-chain аудита на записи %d: %s (runbook audit-hash-chain-broken.md)",
			rep.BrokenAt, rep.Reason),
		details: map[string]any{"broken_at": rep.BrokenAt, "reason": rep.Reason, "checked": rep.Checked},
	}}
}

// audit — событие подъёма в аудит-лог (п. 14.2). Ошибка — лог: алерт уже
// поднят, повторное поднятие не требуется.
func (e *Evaluator) audit(ctx context.Context, action string, f firing) {
	if err := e.st.AppendAudit(ctx, []audit.Event{{
		Actor: actor, Category: audit.CatAlert, Action: action,
		Target: "alert:" + f.rule + ":" + f.target,
		Details: map[string]any{
			"rule": f.rule, "severity": f.severity, "target": f.target, "message": f.message,
		},
		TS: e.nowFn().UTC(),
	}}); err != nil {
		e.log.Error("alerts: аудит подъёма", "rule", f.rule, "error", err)
	}
}

func (e *Evaluator) auditResolved(ctx context.Context, a store.Alert) {
	if err := e.st.AppendAudit(ctx, []audit.Event{{
		Actor: actor, Category: audit.CatAlert, Action: "alert_resolve",
		Target:  "alert:" + a.Rule + ":" + a.Target,
		Details: map[string]any{"rule": a.Rule, "target": a.Target},
		TS:      e.nowFn().UTC(),
	}}); err != nil {
		e.log.Error("alerts: аудит закрытия", "rule", a.Rule, "error", err)
	}
}

func (e *Evaluator) notify(ctx context.Context, event string, f firing) {
	if e.webhook != nil {
		e.webhook.Notify(ctx, event, store.Alert{
			Rule: f.rule, Severity: f.severity, Target: f.target, Message: f.message, Details: f.details,
		})
	}
}

func (e *Evaluator) notifyResolved(ctx context.Context, a store.Alert) {
	if e.webhook != nil {
		e.webhook.Notify(ctx, "resolved", a)
	}
}
