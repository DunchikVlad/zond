package store

import (
	"context"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// Тесты учёта LLM-вызовов (blueprint п. 10.6, п. 11.1, п. 13).

func testCall(id, scanID, verdictID string) AgentCall {
	return AgentCall{
		ID:            id,
		ScanID:        scanID,
		VerdictID:     verdictID,
		AgentID:       "zond-main",
		Model:         "gpt-4o-mini",
		PromptVersion: "1",
		TokensIn:      100,
		TokensOut:     20,
		CostUSD:       0.00027,
		LatencyMS:     450,
		Status:        "ok",
		CreatedAt:     time.Now().UTC(),
	}
}

// TestSaveVerdictsWithCallsRoundTrip — вердикт и вызов коммитятся одной
// транзакцией и видны через ListVerdicts/ListAgentCalls (п. 13).
func TestSaveVerdictsWithCallsRoundTrip(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v := testVerdict("v1", "s1")
	call := testCall("c1", "s1", "v1")
	if err := st.SaveVerdictsWithCalls(ctx, []verdict.Verdict{v}, []AgentCall{call}); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}
	calls, err := st.ListAgentCalls(ctx, "s1")
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("ожидалась 1 запись вызова, получено %d", len(calls))
	}
	c := calls[0]
	if c.ID != "c1" || c.VerdictID != "v1" || c.ScanID != "s1" {
		t.Fatalf("связи вызова искажены: %+v", c)
	}
	if c.AgentID != "zond-main" || c.Model != "gpt-4o-mini" || c.PromptVersion != "1" {
		t.Fatalf("идентичность вызова искажена: %+v", c)
	}
	if c.TokensIn != 100 || c.TokensOut != 20 || c.CostUSD != 0.00027 || c.LatencyMS != 450 {
		t.Fatalf("экономика вызова искажена: %+v", c)
	}
	if c.Cached || c.Status != "ok" {
		t.Fatalf("cached/status искажены: %+v", c)
	}
	got, err := st.ListVerdicts(ctx, "s1")
	if err != nil || len(got) != 1 {
		t.Fatalf("вердикт не сохранился: %v %v", got, err)
	}
}

// TestSaveVerdictsWithCallsCachedFlag — bool Cached мапится на INTEGER.
func TestSaveVerdictsWithCallsCachedFlag(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdicts(t, st, testVerdict("v1", "s1"))
	call := testCall("c1", "s1", "v1")
	call.Cached = true
	call.Status = "cache_hit"
	call.TokensIn, call.TokensOut, call.CostUSD = 0, 0, 0
	if err := st.SaveVerdictsWithCalls(ctx, nil, []AgentCall{call}); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}
	calls, _ := st.ListAgentCalls(ctx, "s1")
	if len(calls) != 1 || !calls[0].Cached || calls[0].Status != "cache_hit" {
		t.Fatalf("cached-запись искажена: %+v", calls)
	}
}

// TestSaveVerdictsWithCallsIdempotentVerdict — повторная вставка вердикта
// (без вызовов) не трогает учётные записи (целостность учёта, п. 13).
func TestSaveVerdictsWithCallsIdempotentVerdict(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v := testVerdict("v1", "s1")
	if err := st.SaveVerdictsWithCalls(ctx, []verdict.Verdict{v}, []AgentCall{testCall("c1", "s1", "v1")}); err != nil {
		t.Fatalf("первая вставка: %v", err)
	}
	v.Confidence = 0.5
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{v}); err != nil {
		t.Fatalf("повторная вставка вердикта: %v", err)
	}
	calls, _ := st.ListAgentCalls(ctx, "s1")
	if len(calls) != 1 {
		t.Fatalf("учётная запись должна остаться одна, получено %d", len(calls))
	}
	got, _ := st.ListVerdicts(ctx, "s1")
	if len(got) != 1 || got[0].Confidence != 0.5 {
		t.Fatalf("вердикт не обновился: %+v", got)
	}
}

// TestSaveVerdictsWithCallsFKViolation — call с несуществующим verdict_id
// откатывает транзакцию (п. 13): ни вердикт, ни вызов не сохраняются.
func TestSaveVerdictsWithCallsFKViolation(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	v := testVerdict("v1", "s1")
	call := testCall("c1", "s1", "ghost-verdict")
	if err := st.SaveVerdictsWithCalls(ctx, []verdict.Verdict{v}, []AgentCall{call}); err == nil {
		t.Fatal("FK-нарушение verdict_id должно откатывать транзакцию")
	}
	if calls, _ := st.ListAgentCalls(ctx, "s1"); len(calls) != 0 {
		t.Fatalf("вызов с битым FK не должен сохраниться: %+v", calls)
	}
	if vs, _ := st.ListVerdicts(ctx, "s1"); len(vs) != 0 {
		t.Fatalf("вердикт из откаченной транзакции не должен сохраниться: %+v", vs)
	}
}

// TestAgentCallBadStatusRejected — CHECK (status IN ...) держит мусор.
func TestAgentCallBadStatusRejected(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdicts(t, st, testVerdict("v1", "s1"))
	call := testCall("c1", "s1", "v1")
	call.Status = "weird"
	if err := st.SaveVerdictsWithCalls(ctx, nil, []AgentCall{call}); err == nil {
		t.Fatal("недопустимый status должен отклоняться CHECK-ограничением")
	}
}

// TestPriceForSeededModels — прайс-лист из миграции 0003 (п. 11.1).
func TestPriceForSeededModels(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		model string
		pin   float64
		pout  float64
		ok    bool
	}{
		{"gpt-4o-mini", 0.15, 0.60, true},
		{"gpt-4o", 2.50, 10.00, true},
		{"unknown-model", 0, 0, false},
	}
	for _, c := range cases {
		pin, pout, ok := st.PriceFor(ctx, c.model, now)
		if ok != c.ok || pin != c.pin || pout != c.pout {
			t.Fatalf("PriceFor(%q) = %v/%v/%v, ожидалось %v/%v/%v", c.model, pin, pout, ok, c.pin, c.pout, c.ok)
		}
	}
}

// TestPriceForEffectiveFrom — действует последняя запись с effective_from <= now.
func TestPriceForEffectiveFrom(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustExec(t, st, `INSERT INTO model_prices (model, per_1m_in, per_1m_out, effective_from)
		VALUES ('gpt-4o-mini', 0.20, 0.80, '2026-06-01')`)
	before := time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	if pin, _, ok := st.PriceFor(ctx, "gpt-4o-mini", before); !ok || pin != 0.15 {
		t.Fatalf("до effective_from должна действовать старая цена: %v %v", pin, ok)
	}
	if pin, pout, ok := st.PriceFor(ctx, "gpt-4o-mini", after); !ok || pin != 0.20 || pout != 0.80 {
		t.Fatalf("после effective_from должна действовать новая цена: %v/%v %v", pin, pout, ok)
	}
}

// TestNewCallIDUnique — идентификаторы вызовов уникальны (crypto/rand hex16).
func TestNewCallIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewCallID()
		if len(id) != 32 || seen[id] || !isHex(id) {
			t.Fatalf("плохой идентификатор вызова: %q", id)
		}
		seen[id] = true
	}
}

func isHex(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// mustExec — вспомогательный INSERT/UPDATE для тестов прайс-листа.
func mustExec(t *testing.T, st *Store, query string) {
	t.Helper()
	if _, err := st.db.Exec(query); err != nil {
		t.Fatalf("exec: %v", err)
	}
}

// TestListAgentCallsOrdersByCreatedAt — порядок: created_at, id (п. 10.6).
func TestListAgentCallsOrdersByCreatedAt(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	mustSaveScan(t, st, "s1")
	mustSaveVerdicts(t, st, testVerdict("v1", "s1"))
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, id := range []string{"c-earlier", "c-later"} {
		call := testCall(id, "s1", "v1")
		call.CreatedAt = base.Add(time.Duration(i) * time.Second)
		if err := st.SaveVerdictsWithCalls(ctx, nil, []AgentCall{call}); err != nil {
			t.Fatalf("вставка %s: %v", id, err)
		}
	}
	calls, err := st.ListAgentCalls(ctx, "s1")
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	if len(calls) != 2 || calls[0].ID != "c-earlier" || calls[1].ID != "c-later" {
		t.Fatalf("порядок по created_at нарушен: %+v", calls)
	}
	// валидация, что scan_id фильтрует чужие прогоны
	if calls, _ := st.ListAgentCalls(ctx, "ghost"); len(calls) != 0 {
		t.Fatalf("чужие прогоны не должны попадать в выборку: %+v", calls)
	}
}
