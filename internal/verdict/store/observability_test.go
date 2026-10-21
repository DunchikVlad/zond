// Тесты агрегатов наблюдаемости (blueprint п. 17): оконные метрики вызовов,
// серия ошибок llm_unavailable, сводка последних прогонов по источникам,
// действия ревью.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
)

func obsCall(scanID, verdictID, status string, latency int64, createdAt time.Time) AgentCall {
	return AgentCall{
		ID: NewCallID(), ScanID: scanID, VerdictID: verdictID,
		AgentID: "zond-main", Model: "gpt-4o-mini",
		TokensIn: 100, TokensOut: 20, CostUSD: 0.001, LatencyMS: latency,
		Status: status, CreatedAt: createdAt,
	}
}

// TestLLMWindowStats — агрегаты за окно: вызовы (ok+error), ошибки, кэш,
// токены, стоимость; latency ok-вызовов отсортированы.
func TestLLMWindowStats(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)

	mustSaveScan(t, st, "s1")
	vs := []verdict.Verdict{
		{ID: "v1", ScanID: "s1", Table: "t", Path: "c1", Label: "EMAIL",
			ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: now},
	}
	calls := []AgentCall{
		obsCall("s1", "v1", "ok", 30, now),
		obsCall("s1", "v1", "ok", 10, now),
		obsCall("s1", "v1", "error", 0, now),
		obsCall("s1", "v1", "cache_hit", 0, now),
		obsCall("s1", "v1", "ok", 999, old), // вне окна
	}
	if err := st.SaveVerdictsWithCalls(ctx, vs, calls, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}

	w, err := st.LLMWindowStats(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("LLMWindowStats: %v", err)
	}
	if w.Calls != 3 || w.Errors != 1 || w.CacheHits != 1 {
		t.Errorf("calls/errors/cache = %d/%d/%d, ожидалось 3/1/1", w.Calls, w.Errors, w.CacheHits)
	}
	if w.TokensIn != 200 || w.TokensOut != 40 {
		t.Errorf("tokens = %d/%d, ожидалось 200/40 (2 ok-вызова в окне)", w.TokensIn, w.TokensOut)
	}
	if w.CostUSD != 0.002 {
		t.Errorf("cost = %v, ожидалось 0.002", w.CostUSD)
	}
	if len(w.Latencies) != 2 || w.Latencies[0] != 10 || w.Latencies[1] != 30 {
		t.Errorf("latencies = %v, ожидалось [10 30] (ok, по возрастанию)", w.Latencies)
	}
}

// TestLLMErrorStreak — серия последних подряд ошибок; одно ok обнуляет.
// created_at с секундной точностью: порядок в пределах секунды — по rowid
// (порядок вставки), поэтому вставляем строго последовательно.
func TestLLMErrorStreak(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mustSaveScan(t, st, "s1")
	// verdict_id — FK: нужен вердикт (upsert идемпотентен).
	if err := st.SaveVerdicts(ctx, []verdict.Verdict{
		{ID: "v1", ScanID: "s1", Table: "t", Path: "c1", Label: "EMAIL",
			ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: now},
	}); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
	mk := func(status string) {
		t.Helper()
		if err := st.SaveVerdictsWithCalls(ctx, nil, []AgentCall{obsCall("s1", "v1", status, 0, now)}, nil); err != nil {
			t.Fatalf("insert %s: %v", status, err)
		}
	}
	mk("ok")
	for i := 0; i < 6; i++ {
		mk("error")
	}
	streak, err := st.LLMErrorStreak(ctx, 6)
	if err != nil {
		t.Fatalf("LLMErrorStreak: %v", err)
	}
	if streak != 6 {
		t.Errorf("streak = %d, ожидалось 6 (шесть ошибок подряд)", streak)
	}
	mk("ok")
	streak, _ = st.LLMErrorStreak(ctx, 6)
	if streak != 0 {
		t.Errorf("streak после ok = %d, ожидалось 0", streak)
	}
}

// TestLatestScanOverviews — по каждому источнику берётся ПОСЛЕДНИЙ прогон
// (MAX started_at): pending, колонки, llm-колонки (без кэша), no_llm_share.
func TestLatestScanOverviews(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	old := &Scan{ID: "ch-old", SourceName: "ch", Profile: "deep", Status: "done", StartedAt: now.Add(-2 * time.Hour)}
	newer := &Scan{ID: "ch-new", SourceName: "ch", Profile: "deep", Status: "done", StartedAt: now.Add(-time.Hour)}
	mg := &Scan{ID: "mg-1", SourceName: "mongo", Profile: "deep", Status: "budget_exceeded", StartedAt: now}
	for _, sc := range []*Scan{old, newer, mg} {
		if err := st.SaveScan(ctx, sc); err != nil {
			t.Fatalf("SaveScan %s: %v", sc.ID, err)
		}
	}

	vs := []verdict.Verdict{
		{ID: "v1", ScanID: "ch-new", Table: "t", Path: "c1", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
		{ID: "v2", ScanID: "ch-new", Table: "t", Path: "c2", Label: "PHONE", ReviewStatus: verdict.StatusPending, CreatedAt: now},
		{ID: "v3", ScanID: "ch-new", Table: "t", Path: "c3", Label: "TAX_ID", ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: now},
		{ID: "v4", ScanID: "ch-new", Table: "t", Path: "c4", Label: "EMAIL", ReviewStatus: verdict.StatusAutoAccepted, CreatedAt: now},
		{ID: "v5", ScanID: "mg-1", Table: "t", Path: "c5", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
		// вердикт старого прогона не должен попасть в сводку
		{ID: "v6", ScanID: "ch-old", Table: "t", Path: "c6", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
	}
	calls := []AgentCall{
		obsCall("ch-new", "v3", "ok", 10, now),
		obsCall("ch-new", "v3", "cache_hit", 0, now), // кэш не считается llm-колонкой
	}
	if err := st.SaveVerdictsWithCalls(ctx, vs, calls, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}

	ov, err := st.LatestScanOverviews(ctx)
	if err != nil {
		t.Fatalf("LatestScanOverviews: %v", err)
	}
	if len(ov) != 2 {
		t.Fatalf("овервью = %d, ожидалось 2 (ch, mongo)", len(ov))
	}
	bySource := map[string]SourceOverview{}
	for _, o := range ov {
		bySource[o.Source] = o
	}
	ch := bySource["ch"]
	if ch.ScanID != "ch-new" || ch.Columns != 4 || ch.LLMColumns != 1 || ch.Pending != 2 {
		t.Errorf("ch: %+v, ожидалось scan=ch-new columns=4 llm=1 pending=2", ch)
	}
	if ch.NoLLMShare != 0.75 {
		t.Errorf("ch no_llm_share = %v, ожидалось 0.75", ch.NoLLMShare)
	}
	mgv := bySource["mongo"]
	if mgv.ScanID != "mg-1" || mgv.Status != "budget_exceeded" || mgv.Pending != 1 || mgv.LLMColumns != 0 {
		t.Errorf("mongo: %+v", mgv)
	}
}

// TestReviewActionCounts — действия ревью за окно (доля confirmed, п. 17).
func TestReviewActionCounts(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	now := time.Now().UTC()

	mustSaveScan(t, st, "s1")
	vs := []verdict.Verdict{
		{ID: "v1", ScanID: "s1", Table: "t", Path: "c1", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
		{ID: "v2", ScanID: "s1", Table: "t", Path: "c2", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
		{ID: "v3", ScanID: "s1", Table: "t", Path: "c3", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
	}
	if err := st.SaveVerdicts(ctx, vs); err != nil {
		t.Fatalf("SaveVerdicts: %v", err)
	}
	if _, err := st.ApplyReview(ctx, "v1", ReviewConfirm, "", "sso:tester", now); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := st.ApplyReview(ctx, "v2", ReviewReject, "", "sso:tester", now); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, err := st.ApplyReview(ctx, "v3", ReviewRelabel, verdict.Label("PHONE"), "sso:tester", now); err != nil {
		t.Fatalf("relabel: %v", err)
	}

	acts, err := st.ReviewActionCounts(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("ReviewActionCounts: %v", err)
	}
	if acts["confirm"] != 1 || acts["reject"] != 1 || acts["relabel"] != 1 {
		t.Errorf("actions = %v, ожидалось по одному", acts)
	}
	old, err := st.ReviewActionCounts(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("ReviewActionCounts (пустое окно): %v", err)
	}
	if len(old) != 0 {
		t.Errorf("пустое окно: %v", old)
	}
}
