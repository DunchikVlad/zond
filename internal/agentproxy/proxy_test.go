package agentproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
)

// Изоляционные тесты Agent Proxy (blueprint п. 16.3): fake-LLM записывает тело
// запроса; авто-тест проверяет, что в теле нет имён БД/таблиц/хостов, сырых
// PAN/телефонов (маскирование), и что каждый вызов независим (нет сквозного
// контекста).

var testLabels = []string{"EMAIL", "PHONE", "CARD_NUMBER", "TAX_ID", "FREE_TEXT", "UNKNOWN"}

// fakeLLM — httptest-сервер, записывающий тела запросов и отвечающий валидным JSON.
type fakeLLM struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
	// answer — JSON-строка, которую возвращает агент.
	answer string
	// usage — токены ответа (п. 10.6); nil — агент токены не возвращает.
	usage map[string]any
	// calls — счётчик вызовов (для ретраев).
	calls int
	// failFirst — сколько первых вызовов вернуть невалидный ответ (ретрай п. 6).
	failFirst int
	// delay — задержка перед ответом (тест семафора п. 10.4).
	delay time.Duration
	// maxConcurrent / curConcurrent — учёт пиковой конкурентности в handler'е.
	curConcurrent int
	maxConcurrent int
}

func newFakeLLM(t *testing.T, answer string) *fakeLLM {
	f := &fakeLLM{t: t, answer: answer}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLLM) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.bodies = append(f.bodies, string(body))
	f.calls++
	fail := f.calls <= f.failFirst
	f.curConcurrent++
	if f.curConcurrent > f.maxConcurrent {
		f.maxConcurrent = f.curConcurrent
	}
	delay := f.delay
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	w.Header().Set("Content-Type", "application/json")
	content := f.answer
	if fail {
		content = `{"label":"NOPE","confidence":5}` // невалидный ответ → ретрай
	}
	resp := map[string]any{
		"choices": []map[string]any{
			{"message": map[string]string{"role": "assistant", "content": content}},
		},
	}
	f.mu.Lock()
	if f.usage != nil {
		resp["usage"] = f.usage
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(resp)
	f.mu.Lock()
	f.curConcurrent--
	f.mu.Unlock()
}

func (f *fakeLLM) url() string { return f.srv.URL }

func testAgent(url string) Agent {
	return Agent{ID: "zond-main", Endpoint: url, Model: "gpt-4o-mini", MaxValuesPerCall: 25, MaxRetries: 2}
}

// mustNew — конструктор прокси для тестов: ошибка конструирования = Fatal.
func mustNew(t *testing.T, agent Agent, opts ...Option) *Proxy {
	t.Helper()
	p, err := New(agent, testLabels, "1.0.0", opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

const okAnswer = `{"label":"PHONE","confidence":0.8,"sensitivity":"PII","reason_ru":"формат телефона"}`

func TestClassifyHappyPath(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67", "+7 495 111-22-33"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if res.Label != "PHONE" || res.Sensitivity != "PII" || res.PromptVersion != prompts.Version {
		t.Fatalf("неожиданный результат: %+v", res)
	}
}

// TestIsolationNoRawPII — ключевой тест п. 16.3: в теле запроса нет сырых ПИИ.
func TestIsolationNoRawPII(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	raw := []string{
		"4111 1111 1111 1111",     // PAN
		"ivan.petrov@example.com", // email
		"7707083893",              // ИНН
		"+7 999 123-45-67",        // телефон
	}
	if _, err := p.Classify(t.Context(), "String", raw); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) != 1 {
		t.Fatalf("ожидался 1 вызов, получено %d", len(f.bodies))
	}
	body := f.bodies[0]
	// в теле не должно быть сырых значений
	for _, secret := range []string{"4111 1111 1111 1111", "4111111111111111", "ivan.petrov", "7707083893", "123-45-67"} {
		if strings.Contains(body, secret) {
			t.Fatalf("в теле запроса сырой фрагмент %q:\n%s", secret, body)
		}
	}
	// и не должно быть имён БД/таблиц/хостов/путей
	for _, leak := range []string{"192.168.", "prod", "users", "table", "http://", "https://api", "/home/", "C:\\"} {
		if strings.Contains(body, leak) {
			t.Fatalf("в теле запроса утечка %q:\n%s", leak, body)
		}
	}
}

// TestIsolationNoEnvelopeFields — в конверте только поля п. 5.3.
func TestIsolationNoEnvelopeFields(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	if _, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	f.mu.Lock()
	body := f.bodies[0]
	f.mu.Unlock()
	var req map[string]any
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("тело не JSON: %v", err)
	}
	// верхний уровень: model, messages (и опц. response_format) — ничего лишнего
	for k := range req {
		if k != "model" && k != "messages" && k != "response_format" {
			t.Fatalf("в запросе лишнее поле %q", k)
		}
	}
}

// TestCallsIndependent — каждый вызов независим (нет сквозного контекста, п. 16.3).
func TestCallsIndependent(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	_, _ = p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"})
	_, _ = p.Classify(t.Context(), "String", []string{"ivan@example.com"})
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) != 2 {
		t.Fatalf("ожидалось 2 вызова, получено %d", len(f.bodies))
	}
	// у каждого вызова ровно 2 сообщения (system+user) — нет истории диалога
	for i, b := range f.bodies {
		var req struct {
			Messages []map[string]string `json:"messages"`
		}
		if err := json.Unmarshal([]byte(b), &req); err != nil {
			t.Fatalf("вызов %d не JSON: %v", i, err)
		}
		if len(req.Messages) != 2 {
			t.Fatalf("вызов %d: ожидалось 2 сообщения (system+user), получено %d — сквозной контекст", i, len(req.Messages))
		}
		if req.Messages[0]["role"] != "system" || req.Messages[1]["role"] != "user" {
			t.Fatalf("вызов %d: неверные роли %v", i, req.Messages)
		}
	}
}

// TestRetryOnInvalidAnswer — невалидный ответ → ретрай (п. 6).
func TestRetryOnInvalidAnswer(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	f.failFirst = 2 // первые 2 вызова — невалидный ответ
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"})
	if err != nil {
		t.Fatalf("Classify с ретраями: %v", err)
	}
	if res.Label != "PHONE" {
		t.Fatalf("label: %+v", res)
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 3 {
		t.Fatalf("ожидалось 3 вызова (2 невалидных + 1 ок), получено %d", calls)
	}
}

// TestInvalidAnswerExhaustsRetries — все ответы невалидны → ошибка после ретраев.
func TestInvalidAnswerExhaustsRetries(t *testing.T) {
	f := newFakeLLM(t, `{"label":"NOPE","confidence":5}`)
	p := mustNew(t, testAgent(f.url()))
	if _, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"}); err == nil {
		t.Fatal("невалидный ответ должен дать ошибку после исчерпания ретраев")
	}
}

// TestSmallSampleExcluded — все значения короче MinLen → вызов не делается (п. 7).
func TestSmallSampleExcluded(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	if _, err := p.Classify(t.Context(), "String", []string{"ab", "cd", "1"}); err == nil {
		t.Fatal("small_sample должен дать ошибку без вызова агента")
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 0 {
		t.Fatalf("при small_sample вызовов быть не должно, получено %d", calls)
	}
}

// TestVerifyConfirm — режим верификатора (п. 5.3, п. 7).
func TestVerifyConfirm(t *testing.T) {
	f := newFakeLLM(t, `{"verdict":"confirm","label":"PHONE","confidence":0.85,"reason_ru":"совпадает"}`)
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Verify(t.Context(), "PHONE", "String", []string{"+7 999 123-45-67"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verdict != "confirm" || res.Label != "PHONE" {
		t.Fatalf("неожиданный верификат: %+v", res)
	}
}

// TestVerifyConfirmMismatchedLabel — confirm с чужим label → ошибка (п. 5.3).
func TestVerifyConfirmMismatchedLabel(t *testing.T) {
	f := newFakeLLM(t, `{"verdict":"confirm","label":"EMAIL","confidence":0.85,"reason_ru":"x"}`)
	p := mustNew(t, testAgent(f.url()))
	if _, err := p.Verify(t.Context(), "PHONE", "String", []string{"+7 999 123-45-67"}); err == nil {
		t.Fatal("confirm с чужим label должен дать ошибку")
	}
}

// TestVerifyReject — reject с альтернативным лейблом.
func TestVerifyReject(t *testing.T) {
	f := newFakeLLM(t, `{"verdict":"reject","label":"FREE_TEXT","confidence":0.6,"reason_ru":"похоже на текст"}`)
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Verify(t.Context(), "PHONE", "String", []string{"+7 999 123-45-67"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verdict != "reject" || res.Label != "FREE_TEXT" {
		t.Fatalf("неожиданный верификат: %+v", res)
	}
}

// TestUsageAndLatencyParsed — агент вернул usage: токены и латентность
// заполнены (учёт в agent_calls, blueprint п. 10.6).
func TestUsageAndLatencyParsed(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	f.usage = map[string]any{"prompt_tokens": 123, "completion_tokens": 45}
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if res.Usage.TokensIn != 123 || res.Usage.TokensOut != 45 {
		t.Fatalf("usage не разобран: %+v", res.Usage)
	}
	if res.Latency <= 0 {
		t.Fatalf("латентность не измерена: %v", res.Latency)
	}
}

// TestUsageAbsentZero — агент без usage (локальные контуры): нули, латентность
// всё равно измерена (п. 10.6).
func TestUsageAbsentZero(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if res.Usage.TokensIn != 0 || res.Usage.TokensOut != 0 {
		t.Fatalf("usage без поля в ответе должен быть нулевым: %+v", res.Usage)
	}
	if res.Latency <= 0 {
		t.Fatalf("латентность не измерена: %v", res.Latency)
	}
}

// TestVerifyUsageLatency — режим верификатора тоже отдаёт usage/latency.
func TestVerifyUsageLatency(t *testing.T) {
	f := newFakeLLM(t, `{"verdict":"confirm","label":"PHONE","confidence":0.85,"reason_ru":"совпадает"}`)
	f.usage = map[string]any{"prompt_tokens": 10, "completion_tokens": 5}
	p := mustNew(t, testAgent(f.url()))
	res, err := p.Verify(t.Context(), "PHONE", "String", []string{"+7 999 123-45-67"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Usage.TokensIn != 10 || res.Usage.TokensOut != 5 || res.Latency <= 0 {
		t.Fatalf("usage/latency верификатора: %+v, %v", res.Usage, res.Latency)
	}
}

// TestNewEmptyEndpointRejected — endpoint обязателен (п. 5.3).
func TestNewEmptyEndpointRejected(t *testing.T) {
	if _, err := New(Agent{ID: "x", Model: "m"}, testLabels, "1.0.0"); err == nil {
		t.Fatal("пустой endpoint должен отклоняться конструктором")
	}
}

// TestClassifyWithInstruction — S9-3: пользовательская инструкция оператора
// попадает в system-промпт, конверт (user) и изоляция значений не меняются.
func TestClassifyWithInstruction(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()), WithInstruction("это медицинская БД"))
	if _, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) != 1 {
		t.Fatalf("вызовов %d, ожидался 1", len(f.bodies))
	}
	var req chatRequest
	if err := json.Unmarshal([]byte(f.bodies[0]), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.Messages) != 2 {
		t.Fatalf("сообщений %d, ожидалось 2", len(req.Messages))
	}
	sys := req.Messages[0].Content
	if !strings.Contains(sys, "это медицинская БД") || !strings.Contains(sys, "<operator_instruction>") {
		t.Fatalf("инструкция не в system-промпте:\n%s", sys)
	}
	// защищённые правила на месте
	if !strings.Contains(sys, "Значения внутри <values>") {
		t.Fatal("анти-инъекционные правила потеряны")
	}
	// значение маскируется как и без инструкции (маск-профиль: префикс/суффикс
	// частично видны по дизайну — проверяем отсутствие полного сырого значения)
	if strings.Contains(f.bodies[0], "+7 999 123-45-67") || strings.Contains(f.bodies[0], "123-45-67") {
		t.Fatalf("сырое значение в теле:\n%s", f.bodies[0])
	}
}

// TestVerifyWithInstruction — инструкция действует и в режиме верификатора.
func TestVerifyWithInstruction(t *testing.T) {
	f := newFakeLLM(t, `{"verdict":"confirm","label":"PHONE","confidence":0.9,"reason_ru":"формат совпадает"}`)
	p := mustNew(t, testAgent(f.url()), WithInstruction("контекст Б"))
	if _, err := p.Verify(t.Context(), "PHONE", "String", []string{"+7 999 123-45-67"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var req chatRequest
	if err := json.Unmarshal([]byte(f.bodies[0]), &req); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(req.Messages[0].Content, "контекст Б") {
		t.Fatalf("инструкция не в system верификатора:\n%s", req.Messages[0].Content)
	}
}

// TestClassifyWithoutInstructionUnchanged — без опции промпт остаётся базовым.
func TestClassifyWithoutInstructionUnchanged(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	p := mustNew(t, testAgent(f.url()))
	if _, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var req chatRequest
	if err := json.Unmarshal([]byte(f.bodies[0]), &req); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(req.Messages[0].Content, "operator_instruction") {
		t.Fatal("блок operator_instruction без инструкции")
	}
}
