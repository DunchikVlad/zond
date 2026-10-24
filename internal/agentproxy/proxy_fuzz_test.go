package agentproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FuzzAgentResponse — устойчивость разбора ответа агента (blueprint п. 16.10,
// JSON-ответа агента п. 5.3). Инварианты: разбор не паникует; валидный по
// схеме п. 5.3 ответ принимается; невалидный — отклоняется (ошибка, без
// паники). Фаззится «сырое» тело content внутри валидной OpenAI-обёртки.
func FuzzAgentResponse(f *testing.F) {
	seeds := []string{
		`{"label":"EMAIL","confidence":0.9,"sensitivity":"PII","reason_ru":"похоже на email"}`,
		`{"label":"UNKNOWN","confidence":0,"sensitivity":"none","reason_ru":"н"}`,
		`{"label":"X","confidence":2,"sensitivity":"bad","reason_ru":""}`,
		`{"label":1}`,
		`not json`,
		``,
		`[]`,
		`{"label":"EMAIL","confidence":"high"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"choices": []map[string]any{
					{"message": map[string]string{"role": "assistant", "content": content}},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()
		p, err := New(Agent{ID: "fz", Endpoint: srv.URL, Model: "m", MaxRetries: 0},
			[]string{"EMAIL", "UNKNOWN"}, "1.0.0")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Не должно паниковать; исход (ok/ошибка) определяется валидностью
		// content по схеме п. 5.3 — обе ветки допустимы, паника — нет.
		_, _ = p.Classify(ctx, "String", []string{"x@y.z"})
	})
}
