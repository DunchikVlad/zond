// Тесты S9-2 веб-UI: фильтр llm_status на странице вердиктов, колонка LLM,
// фрагмент вызовов /verdicts/{id}/calls (HTMX) с экранированием reason_ru/error.
package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// TestVerdictsPageLLMStatus — страница /verdicts содержит select llm_status и
// колонку LLM; мягкая валидация: неизвестный статус игнорируется (S9-2).
func TestVerdictsPageLLMStatus(t *testing.T) {
	st := fixtureStore(t)
	sessions := auth.NewSessionStore(0)
	ts, _ := newTestServer(t, st, sessions, false, &fakeRunner{})

	code, body := get(t, ts.Client(), ts.URL+"/verdicts")
	if code != http.StatusOK {
		t.Fatalf("/verdicts: %d", code)
	}
	if !strings.Contains(body, `name="llm_status"`) {
		t.Fatal("нет select llm_status в форме фильтров")
	}
	if !strings.Contains(body, "<th>LLM</th>") {
		t.Fatal("нет колонки LLM в таблице")
	}
	if !strings.Contains(body, "/verdicts/v1/calls") {
		t.Fatal("нет HTMX-загрузки вызовов в ячейке евиденса")
	}
	// известный статус — фильтр применён (fixture-вердикт без статуса не попадает)
	code, body = get(t, ts.Client(), ts.URL+"/verdicts?llm_status=called")
	if code != http.StatusOK || !strings.Contains(body, `Всего под фильтром: 0`) {
		t.Fatalf("фильтр called: %d", code)
	}
	// неизвестный статус игнорируется — всё равно все вердикты
	code, body = get(t, ts.Client(), ts.URL+"/verdicts?llm_status=bogus")
	if code != http.StatusOK || !strings.Contains(body, `Всего под фильтром: 1`) {
		t.Fatalf("мягкая валидация: %d", code)
	}
}

// TestVerdictCallsFragment — фрагмент вызовов LLM вердикта: данные вызова
// на месте, <script> в reason_ru/error экранируется html/template (п. 14).
func TestVerdictCallsFragment(t *testing.T) {
	st := fixtureStore(t)
	ctx := context.Background()
	call := store.AgentCall{
		ID: "c1", ScanID: "scan-1", VerdictID: "v1", AgentID: "zond-main", Model: "gpt-4o-mini",
		Operation: store.CallOpClassify, PromptVersion: "1",
		TokensIn: 100, TokensOut: 20, CostUSD: 0.000027, LatencyMS: 450, Status: "ok",
		AnswerLabel: "EMAIL", AnswerConfidence: 0.9, AnswerSensitivity: "PII",
		ReasonRU:  "маскированные email <script>alert(1)</script>",
		CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveVerdictsWithCalls(ctx, nil, []store.AgentCall{call}, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}
	call2 := call
	call2.ID = "c2"
	call2.Operation = store.CallOpVerify
	call2.Status = "error"
	call2.ReasonRU = ""
	call2.Error = "agentproxy: HTTP 500 <script>alert(2)</script>"
	if err := st.SaveVerdictsWithCalls(ctx, nil, []store.AgentCall{call2}, nil); err != nil {
		t.Fatalf("вторая запись: %v", err)
	}

	sessions := auth.NewSessionStore(0)
	ts, _ := newTestServer(t, st, sessions, false, &fakeRunner{})

	code, body := get(t, ts.Client(), ts.URL+"/verdicts/v1/calls")
	if code != http.StatusOK {
		t.Fatalf("фрагмент: %d", code)
	}
	for _, want := range []string{"classify", "verify", "zond-main/gpt-4o-mini",
		"EMAIL", "0.90", "$0.0000", "промпт v1", "маскированные email"} {
		if !strings.Contains(body, want) {
			t.Errorf("нет %q в фрагменте:\n%.500s", want, body)
		}
	}
	if strings.Contains(body, "<script>alert") {
		t.Fatalf("сырой <script> в фрагменте (экранирование п. 14):\n%.500s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("экранированный script не найден:\n%.500s", body)
	}
	// вердикт без вызовов — заглушка
	code, body = get(t, ts.Client(), ts.URL+"/verdicts/ghost/calls")
	if code != http.StatusNotFound {
		t.Fatalf("404 фрагмента: %d", code)
	}
}
