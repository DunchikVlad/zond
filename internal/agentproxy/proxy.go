// Package agentproxy — единственная точка вызова LLM (blueprint п. 10).
// Формирует тело запроса строго по п. 5.3 (изоляция — ни один другой пакет не
// импортирует HTTP-клиент LLM, контролируется depguard), маскирует значения
// через mask/, валидирует ответ по схеме, ретраит невалидные ответы (п. 6).
package agentproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy/mask"
	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
)

// Agent — конфигурация одного LLM-агента (реестр detectors.yaml, п. 5.3).
type Agent struct {
	ID               string
	Endpoint         string
	Model            string
	APIKey           string // уже разрешённый из env (не имя переменной)
	MaxValuesPerCall int
	Timeout          time.Duration
	MaxRetries       int
}

// ClassifyResult — валидированный ответ агента (п. 5.3).
type ClassifyResult struct {
	Label         string
	Confidence    float64
	Sensitivity   string
	ReasonRU      string
	PromptVersion string
	Usage         Usage         // токены вызова (п. 10.6, учёт в agent_calls)
	Latency       time.Duration // полная длительность call() включая ретраи (п. 10.6)
}

// VerifyResult — ответ верификатора (п. 5.3: confirm|reject + label).
type VerifyResult struct {
	Verdict    string // confirm | reject
	Label      string
	Confidence float64
	ReasonRU   string
	Usage      Usage
	Latency    time.Duration
}

// Usage — токены одного вызова (blueprint п. 10.6; cost_usd считает движок
// по прайс-листу model_prices, п. 11.1).
type Usage struct {
	TokensIn  int
	TokensOut int
}

// Proxy — клиент Agent Proxy. Сессии: один вызов = один system+user (п. 10.3).
type Proxy struct {
	agent      Agent
	labels     []string // enum лейблов таксономии
	taxVersion string
	http       *http.Client
	gate       *Gate  // лимиты п. 10.4; nil — без ограничений
	policy     Policy // egress п. 10.7; пустая — проверка отключена
}

// Option — опция конструктора Proxy (лимиты и egress-политика).
type Option func(*Proxy)

// WithGate подключает лимитер вызовов: семафор + rate-limit (blueprint п. 10.4).
// Gate разделяется между всеми прокси одного скана.
func WithGate(g *Gate) Option {
	return func(p *Proxy) { p.gate = g }
}

// WithPolicy задаёт egress-политику (blueprint п. 10.7). Нулевая Policy —
// базовая политика пункта (private/loopback разрешены, публичные запрещены);
// отключить проверку нельзя — она выполняется всегда в конструкторе.
func WithPolicy(pol Policy) Option {
	return func(p *Proxy) { p.policy = pol }
}

// New собирает прокси для агента; labels — имена лейблов из taxonomy.yaml.
// Endpoint обязателен и всегда проверяется по egress-политике (п. 10.7,
// fail-fast): прокси с запрещённым эндпоинтом не конструируется.
func New(agent Agent, labels []string, taxonomyVersion string, opts ...Option) (*Proxy, error) {
	if agent.Endpoint == "" {
		return nil, errors.New("agentproxy: endpoint агента обязателен (п. 5.3)")
	}
	if agent.MaxValuesPerCall <= 0 {
		agent.MaxValuesPerCall = 25
	}
	if agent.Timeout <= 0 {
		agent.Timeout = 30 * time.Second
	}
	p := &Proxy{
		agent:      agent,
		labels:     labels,
		taxVersion: taxonomyVersion,
		http:       &http.Client{Timeout: agent.Timeout},
	}
	for _, opt := range opts {
		opt(p)
	}
	if err := CheckEgress(agent.Endpoint, p.policy); err != nil {
		return nil, err
	}
	return p, nil
}

// chatRequest — OpenAI-compatible тело (response_format: json_schema, п. 5.3).
type chatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
}

// chatResponse — минимальная структура OpenAI-ответа. usage — опционально:
// локальные контура (Ollama и т.п.) могут не возвращать токены (п. 10.6).
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage,omitempty"`
}

// answerSchema — ответ классификатора (п. 5.3).
type answerSchema struct {
	Label       string  `json:"label"`
	Confidence  float64 `json:"confidence"`
	Sensitivity string  `json:"sensitivity"`
	ReasonRU    string  `json:"reason_ru"`
}

// verifierSchema — ответ верификатора (п. 5.3).
type verifierSchema struct {
	Verdict    string  `json:"verdict"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
	ReasonRU   string  `json:"reason_ru"`
}

// Classify вызывает агента для колонки: маскирует значения, формирует конверт
// п. 5.3, валидирует ответ. Значения короче mask.MinLen исключаются (п. 10.2).
// Один вызов = один слот лимитера (п. 10.3/10.4); usage и latency — для п. 10.6.
func (p *Proxy) Classify(ctx context.Context, nativeType string, values []string) (*ClassifyResult, error) {
	masked := maskValues(values, p.agent.MaxValuesPerCall)
	if len(masked) == 0 {
		return nil, errors.New("agentproxy: после маскирования нет значений (small_sample)")
	}
	if p.gate != nil {
		if err := p.gate.Acquire(ctx); err != nil {
			return nil, fmt.Errorf("agentproxy: лимит вызовов: %w", err)
		}
		defer p.gate.Release()
	}
	sys := prompts.System(p.labels)
	usr := prompts.User(nativeType, p.taxVersion, masked)
	var ans answerSchema
	start := time.Now()
	_, usage, err := p.call(ctx, sys, usr, func(b []byte) error {
		if err := json.Unmarshal(b, &ans); err != nil {
			return fmt.Errorf("невалидный JSON ответа: %w", err)
		}
		return p.validateAnswer(&ans)
	})
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}
	res := &ClassifyResult{
		Label: ans.Label, Confidence: ans.Confidence, Sensitivity: ans.Sensitivity,
		ReasonRU: ans.ReasonRU, PromptVersion: prompts.Version, Latency: latency,
	}
	if usage != nil {
		res.Usage = *usage
	}
	return res, nil
}

// Verify — режим верификатора (п. 5.3, п. 7): кандидат + маскированные значения.
func (p *Proxy) Verify(ctx context.Context, candidate, nativeType string, values []string) (*VerifyResult, error) {
	masked := maskValues(values, p.agent.MaxValuesPerCall)
	if len(masked) == 0 {
		return nil, errors.New("agentproxy: после маскирования нет значений (small_sample)")
	}
	if p.gate != nil {
		if err := p.gate.Acquire(ctx); err != nil {
			return nil, fmt.Errorf("agentproxy: лимит вызовов: %w", err)
		}
		defer p.gate.Release()
	}
	sys := prompts.VerifierSystem(p.labels)
	usr := prompts.VerifierUser(candidate, nativeType, p.taxVersion, masked)
	var vs verifierSchema
	start := time.Now()
	_, usage, err := p.call(ctx, sys, usr, func(b []byte) error {
		if err := json.Unmarshal(b, &vs); err != nil {
			return fmt.Errorf("невалидный JSON верификатора: %w", err)
		}
		if vs.Verdict != "confirm" && vs.Verdict != "reject" {
			return fmt.Errorf("verdict %q не confirm|reject", vs.Verdict)
		}
		if !p.labelOK(vs.Label) {
			return fmt.Errorf("label %q не из таксономии", vs.Label)
		}
		if vs.Verdict == "confirm" && vs.Label != candidate {
			return fmt.Errorf("confirm с чужим label %q (кандидат %q)", vs.Label, candidate)
		}
		return nil
	})
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}
	res := &VerifyResult{Verdict: vs.Verdict, Label: vs.Label, Confidence: vs.Confidence, ReasonRU: vs.ReasonRU, Latency: latency}
	if usage != nil {
		res.Usage = *usage
	}
	return res, nil
}

// validateAnswer — строгая валидация по схеме п. 5.3 (невалидный ответ → ретрай).
func (p *Proxy) validateAnswer(a *answerSchema) error {
	if !p.labelOK(a.Label) {
		return fmt.Errorf("agentproxy: label %q не из таксономии", a.Label)
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		return fmt.Errorf("agentproxy: confidence %v вне [0,1]", a.Confidence)
	}
	switch a.Sensitivity {
	case "PII", "PCI", "PHI", "none":
	default:
		return fmt.Errorf("agentproxy: sensitivity %q недопустим", a.Sensitivity)
	}
	if n := len([]rune(a.ReasonRU)); n < 1 || n > 300 {
		return fmt.Errorf("agentproxy: reason_ru длиной %d вне [1,300]", n)
	}
	return nil
}

func (p *Proxy) labelOK(l string) bool {
	for _, x := range p.labels {
		if x == l {
			return true
		}
	}
	return false
}

// call — HTTP-вызов с ретраями сбоев и невалидных ответов (п. 6, п. 10.3).
// validate разбирает и проверяет тело; невалидный ответ → ретрай. Возвращает
// usage успешной попытки (может быть nil, если агент токены не вернул).
func (p *Proxy) call(ctx context.Context, system, user string, validate func([]byte) error) ([]byte, *Usage, error) {
	var lastErr error
	attempts := p.agent.MaxRetries + 1
	for i := 0; i < attempts; i++ {
		body, usage, err := p.once(ctx, system, user)
		if err == nil {
			if err := validate(body); err == nil {
				return body, usage, nil
			} else {
				lastErr = fmt.Errorf("agentproxy: %w", err)
			}
		} else {
			lastErr = err
		}
		// экспоненциальная пауза между ретраями (п. 6)
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(time.Duration(1<<uint(i)) * 100 * time.Millisecond):
		}
	}
	return nil, nil, lastErr
}

// once — единичный HTTP-вызов. Единственное место, где формируется и
// отправляется запрос к LLM (изоляция п. 10.1).
func (p *Proxy) once(ctx context.Context, system, user string) ([]byte, *Usage, error) {
	req := chatRequest{Model: p.agent.Model}
	req.Messages = append(req.Messages,
		struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: "system", Content: system},
		struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: "user", Content: user},
	)
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.agent.Endpoint, bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("agentproxy: запрос: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	if p.agent.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+p.agent.APIKey)
	}
	resp, err := p.http.Do(hreq)
	if err != nil {
		return nil, nil, fmt.Errorf("agentproxy: вызов: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("agentproxy: HTTP %d: %s", resp.StatusCode, TruncateForErr(data))
	}
	var cr chatResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, nil, fmt.Errorf("agentproxy: разбор ответа: %w", err)
	}
	if len(cr.Choices) == 0 {
		return nil, nil, errors.New("agentproxy: пустой choices")
	}
	var usage *Usage
	if cr.Usage != nil {
		usage = &Usage{TokensIn: cr.Usage.PromptTokens, TokensOut: cr.Usage.CompletionTokens}
	}
	return []byte(cr.Choices[0].Message.Content), usage, nil
}

// TruncateForErr обрезает тело ошибки для сообщения (без утечки больших тел).
func TruncateForErr(b []byte) string {
	const n = 200
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

// maskValues маскирует и фильтрует значения (короче MinLen исключаются, п. 10.2),
// ограничивает max.
func maskValues(values []string, max int) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		mv, ok := mask.Mask(v)
		if !ok {
			continue
		}
		out = append(out, mv)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}
