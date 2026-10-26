// Тесты S9-2 REST API: llm_status в DTO и фильтре списка вердиктов,
// GET /api/v1/verdicts/{id}/agent-calls (per-column evidence вызовов).
package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// mustVerdictStatus — вердикт с заданным llm_status (S9-2).
func mustVerdictStatus(t *testing.T, st *store.Store, id, scanID, label string, sens verdict.Sensitivity, conf float64, ls verdict.LLMStatus) {
	t.Helper()
	v := verdict.Verdict{
		ID: id, ScanID: scanID, Table: "users", Path: id, NativeType: "String",
		Label: verdict.Label(label), Sensitivity: sens, Confidence: conf,
		EvidenceLayer: verdict.LayerEnsemble, Evidence: map[string]any{"sample": "m***@example.com"},
		LLMStatus: ls, ReviewStatus: verdict.StatusPending, CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveVerdicts(t.Context(), []verdict.Verdict{v}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
}

// TestVerdictListLLMStatusFilter — фильтр llm_status возвращает только нужные;
// невалидный статус — 400 invalid_request.
func TestVerdictListLLMStatusFilter(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	mustVerdictStatus(t, st, "v-called", "s1", "PHONE", verdict.SensitivityPII, 0.9, verdict.LLMStatusCalled)
	mustVerdictStatus(t, st, "v-cache", "s1", "EMAIL", verdict.SensitivityPII, 0.9, verdict.LLMStatusCacheHit)
	mustVerdictStatus(t, st, "v-none", "s1", "PHONE", verdict.SensitivityPII, 0.9, verdict.LLMStatusNotCalled)

	rec := do(t, srv, "GET", "/api/v1/verdicts?scan_id=s1&llm_status=called", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	m := decode(t, rec)
	if m["total"].(float64) != 1 {
		t.Fatalf("total: %v", m["total"])
	}
	items := m["items"].([]any)
	v := items[0].(map[string]any)
	if v["id"] != "v-called" || v["llm_status"] != "called" {
		t.Fatalf("item: %+v", v)
	}
	// cache_hit — своя выборка
	rec = do(t, srv, "GET", "/api/v1/verdicts?scan_id=s1&llm_status=cache_hit", "")
	if m := decode(t, rec); m["total"].(float64) != 1 || m["items"].([]any)[0].(map[string]any)["id"] != "v-cache" {
		t.Fatalf("cache_hit filter: %+v", m)
	}
	// невалидный статус — 400 в конверте п. 11.2
	rec = do(t, srv, "GET", "/api/v1/verdicts?scan_id=s1&llm_status=bogus", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("невалидный llm_status: %d", rec.Code)
	}
	if env := decode(t, rec); env["error"].(map[string]any)["code"] != CodeInvalidRequest {
		t.Fatalf("конверт ошибки: %+v", env)
	}
	// без фильтра — все три
	if m := decode(t, do(t, srv, "GET", "/api/v1/verdicts?scan_id=s1", "")); m["total"].(float64) != 3 {
		t.Fatalf("без фильтра: %+v", m["total"])
	}
}

// TestVerdictAgentCalls — GET /api/v1/verdicts/{id}/agent-calls: 200 с
// размеченными вызовами (S9-2), 404 для отсутствующего вердикта.
func TestVerdictAgentCalls(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "s1", "ch", "done")
	v := verdict.Verdict{
		ID: "v1", ScanID: "s1", Table: "users", Path: "phone", NativeType: "String",
		Label: "PHONE", Sensitivity: verdict.SensitivityPII, Confidence: 0.9,
		EvidenceLayer: verdict.LayerLLM, Evidence: map[string]any{},
		LLMStatus: verdict.LLMStatusCalled, ReviewStatus: verdict.StatusAutoAccepted,
		CreatedAt: time.Now().UTC(),
	}
	calls := []store.AgentCall{{
		ID: "c1", VerdictID: "v1", ScanID: "s1", AgentID: "zond-main", Model: "gpt-4o-mini",
		Operation: store.CallOpClassify, PromptVersion: "1",
		TokensIn: 1000, TokensOut: 100, CostUSD: 0.00021, LatencyMS: 450, Status: "ok",
		AnswerLabel: "PHONE", AnswerConfidence: 0.95, AnswerSensitivity: "PII",
		ReasonRU: "номера мобильных, маскированы", CreatedAt: time.Now().UTC(),
	}, {
		ID: "c2", VerdictID: "v1", ScanID: "s1", AgentID: "zond-main", Model: "gpt-4o-mini",
		Operation: store.CallOpVerify, PromptVersion: "1", LatencyMS: 200, Status: "error",
		Error: "agentproxy: HTTP 500: boom", CreatedAt: time.Now().UTC(),
	}}
	if err := st.SaveVerdictsWithCalls(t.Context(), []verdict.Verdict{v}, calls, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}

	rec := do(t, srv, "GET", "/api/v1/verdicts/v1/agent-calls", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("agent-calls: %d: %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	items := m["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("items: %+v", m)
	}
	c := items[0].(map[string]any)
	if c["id"] != "c1" || c["operation"] != "classify" || c["status"] != "ok" ||
		c["answer_label"] != "PHONE" || c["answer_confidence"] != 0.95 ||
		c["answer_sensitivity"] != "PII" || c["reason_ru"] != "номера мобильных, маскированы" ||
		c["agent_id"] != "zond-main" || c["model"] != "gpt-4o-mini" ||
		c["prompt_version"] != "1" || c["tokens_in"] != 1000.0 || c["tokens_out"] != 100.0 ||
		c["cost_usd"] != 0.00021 || c["latency_ms"] != 450.0 || c["verdict_id"] != "v1" {
		t.Fatalf("classify DTO искажён: %+v", c)
	}
	c = items[1].(map[string]any)
	if c["operation"] != "verify" || c["status"] != "error" || c["error"] != "agentproxy: HTTP 500: boom" {
		t.Fatalf("verify DTO искажён: %+v", c)
	}

	rec = do(t, srv, "GET", "/api/v1/verdicts/ghost/agent-calls", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("404: %d", rec.Code)
	}
	if env := decode(t, rec); env["error"].(map[string]any)["code"] != "verdict_not_found" {
		t.Fatalf("конверт 404: %+v", env)
	}
}

// TestVerdictAgentCallsRBAC — viewer (scope read) видит вызовы: ActionView,
// как и список вердиктов (п. 11.3).
func TestVerdictAgentCallsRBAC(t *testing.T) {
	srv, st, keys := authedServer(t, "")
	mustScan(t, st, "s1", "ch", "done")
	mustVerdict(t, st, "v1", "s1", "EMAIL", verdict.SensitivityPII, 0.9)
	if code := doAuth(t, srv, "GET", "/api/v1/verdicts/v1/agent-calls", "", bearer(keys["reader"])); code != http.StatusOK {
		t.Fatalf("reader agent-calls: %d (ожидался 200)", code)
	}
}
