// Тесты S9-3 веб-UI: форма запуска с user_prompt и per-scan LLM — текст
// нормализуется и доходит до runner; сверхлимитный ввод отклоняется.
package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DunchikVlad/zond/internal/auth"
)

// TestScanStartFormPrompt — форма старта передаёт user_prompt и llm в runner.
func TestScanStartFormPrompt(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	runner := &fakeRunner{}
	ts, _ := newTestServer(t, st, sessions, true, runner)
	admin := sessions.Create("admin@example.com", auth.RoleAdmin)

	post := func(form url.Values) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/scans/start", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.ID})
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: testCSRFToken})
		req.Header.Set(csrfHeader, testCSRFToken)
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	form := url.Values{
		"source": {"ch-test"}, "profile": {"deep"},
		"user_prompt": {"  медицинская БД  "}, "llm": {"true"},
	}
	code, _ := post(form)
	if code != http.StatusFound {
		t.Fatalf("старт с промптом: %d (ожидался 302)", code)
	}
	if runner.lastPrompt != "медицинская БД" {
		t.Fatalf("промпт не нормализован: %q", runner.lastPrompt)
	}
	if runner.lastLLM == nil || *runner.lastLLM != true {
		t.Fatalf("llm-флаг не дошёл: %+v", runner.lastLLM)
	}

	// выключение LLM и пустой промпт
	form.Set("user_prompt", "")
	form.Set("llm", "false")
	if code, _ = post(form); code != http.StatusFound {
		t.Fatalf("llm=false: %d", code)
	}
	if runner.lastPrompt != "" || runner.lastLLM == nil || *runner.lastLLM != false {
		t.Fatalf("пустой промпт/llm=false искажены: %q %+v", runner.lastPrompt, runner.lastLLM)
	}

	// сверхлимитная инструкция — 400, runner не вызван повторно
	big := strings.Repeat("а", 2001)
	form.Set("user_prompt", big)
	form.Set("llm", "")
	before := runner.started
	code, body := post(form)
	if code != http.StatusBadRequest || !strings.Contains(body, "user_prompt") {
		t.Fatalf("сверхлимит: %d, тело %.100q", code, body)
	}
	if runner.started != before {
		t.Fatal("runner вызван при отклонённом промпте")
	}
}

// TestScansPagePromptControls — страница /scans содержит textarea инструкции
// и выбор LLM.
func TestScansPagePromptControls(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	runner := &fakeRunner{}
	ts, _ := newTestServer(t, st, sessions, true, runner)
	admin := sessions.Create("admin@example.com", auth.RoleAdmin)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/scans", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: admin.ID})
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	page := string(b)
	if !strings.Contains(page, `name="user_prompt"`) {
		t.Fatal("textarea user_prompt отсутствует")
	}
	if !strings.Contains(page, `name="llm"`) {
		t.Fatal("выбор llm отсутствует")
	}
}
