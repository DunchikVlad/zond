// Webhook — опциональная внешняя доставка событий алертинга (blueprint
// п. 17; интеграции Slack/Telegram — вне скоупа, п. 20). URL задаётся ENV
// ZOND_ALERT_WEBHOOK (секрет — в env, не в конфиге, п. 12). Fail-closed:
// таймаут, без ретраев; ошибки доставки — в лог, алертинг не роняют.
package observe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// EnvWebhook — имя переменной окружения с URL webhook (п. 12: секреты/env).
const EnvWebhook = "ZOND_ALERT_WEBHOOK"

const webhookTimeout = 5 * time.Second

// Webhook — клиент доставки событий алертов.
type Webhook struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// NewWebhook собирает клиента; пустой URL → nil (доставка отключена).
func NewWebhook(url string, log *slog.Logger) *Webhook {
	if url == "" {
		return nil
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Webhook{
		url:    url,
		client: &http.Client{Timeout: webhookTimeout},
		log:    log,
	}
}

// webhookBody — тело события (без сырых значений; ADR-0010).
type webhookBody struct {
	Event    string         `json:"event"` // raised | resolved
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Target   string         `json:"target"`
	Message  string         `json:"message"`
	Details  map[string]any `json:"details,omitempty"`
	TS       string         `json:"ts"`
}

// Notify отправляет событие алерта; ошибки — лог (не роняют evaluator).
func (w *Webhook) Notify(ctx context.Context, event string, a store.Alert) {
	body, err := json.Marshal(webhookBody{
		Event: event, Rule: a.Rule, Severity: a.Severity, Target: a.Target,
		Message: a.Message, Details: a.Details, TS: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		w.log.Error("webhook: маршалинг", "rule", a.Rule, "error", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		w.log.Error("webhook: запрос", "rule", a.Rule, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		w.log.Error("webhook: доставка", "rule", a.Rule, "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		w.log.Error("webhook: HTTP-статус", "rule", a.Rule, "status", resp.StatusCode,
			"hint", fmt.Sprintf("проверьте %s", EnvWebhook))
	}
}
