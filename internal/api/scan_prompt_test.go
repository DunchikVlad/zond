// Тесты S9-3 REST API: user_prompt и per-scan LLM в старте прогона —
// нормализация и лимит инструкции, строгий разбор JSON, передача в runner.
package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestScanStartUserPrompt — инструкция нормализуется и доходит до runner;
// флаг llm передаётся как *bool; без поля llm — nil (default сервера).
func TestScanStartUserPrompt(t *testing.T) {
	runner := &fakeRunner{started: map[string]string{}}
	srv, _ := newTestServer(t, WithRunner(runner))

	rec := do(t, srv, "POST", "/api/v1/scans",
		`{"source":"ch","profile":"deep","user_prompt":"  медицинская БД  ","llm":true}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d: %s", rec.Code, rec.Body.String())
	}
	if len(runner.opts) != 1 {
		t.Fatalf("runner получил %d стартов", len(runner.opts))
	}
	o := runner.opts[0]
	if o.UserPrompt != "медицинская БД" {
		t.Fatalf("промпт не нормализован: %q", o.UserPrompt)
	}
	if o.LLM == nil || *o.LLM != true {
		t.Fatalf("llm-флаг: %+v", o.LLM)
	}
	if o.Actor != Actor {
		t.Fatalf("actor: %q", o.Actor)
	}

	// явное выключение LLM
	if rec := do(t, srv, "POST", "/api/v1/scans", `{"source":"ch","llm":false}`); rec.Code != http.StatusAccepted {
		t.Fatalf("llm=false: %d", rec.Code)
	}
	if runner.opts[1].LLM == nil || *runner.opts[1].LLM != false {
		t.Fatalf("llm=false не дошёл: %+v", runner.opts[1].LLM)
	}

	// без поля llm — nil (default сервера)
	if rec := do(t, srv, "POST", "/api/v1/scans", `{"source":"ch"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("default llm: %d", rec.Code)
	}
	if runner.opts[2].LLM != nil {
		t.Fatalf("default llm должен быть nil: %+v", runner.opts[2].LLM)
	}
}

// TestScanStartUserPromptRejected — сверхлимитная инструкция, NUL (через
// JSON-escape) и неизвестные поля отклоняются 400 (fail-closed на границе).
func TestScanStartUserPromptRejected(t *testing.T) {
	runner := &fakeRunner{started: map[string]string{}}
	srv, _ := newTestServer(t, WithRunner(runner))

	long := strings.Repeat("а", 2001)
	cases := []string{
		`{"source":"ch","user_prompt":"` + long + `"}`,
		`{"source":"ch","user_prompt":"инструкция\u0000скрытая"}`, // NUL через JSON-escape
		`{"source":"ch","promt":"опечатка в имени поля"}`,
	}
	for _, body := range cases {
		rec := do(t, srv, "POST", "/api/v1/scans", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("тело %q…: ожидался 400, получено %d", body[:40], rec.Code)
		}
		if env := decode(t, rec); env["error"].(map[string]any)["code"] != "invalid_request" {
			t.Fatalf("конверт ошибки: %v", env)
		}
	}
	if len(runner.opts) != 0 {
		t.Fatalf("runner получил отклонённые старты: %+v", runner.opts)
	}
}
