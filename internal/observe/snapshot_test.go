// Тесты BuildSnapshot: перцентили, доля кэша, серия llm_unavailable,
// сводка по источникам, доля confirmed ревью (blueprint п. 17).
package observe

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "snap.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestPercentile — ближайший ранг по возрастающей выборке.
func TestPercentile(t *testing.T) {
	vals := []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	if got := percentile(vals, 0.50); got != 50 {
		t.Errorf("p50 = %d, ожидалось 50", got)
	}
	if got := percentile(vals, 0.95); got != 100 {
		t.Errorf("p95 = %d, ожидалось 100", got)
	}
	if got := percentile(vals, 1.0); got != 100 {
		t.Errorf("p100 = %d, ожидалось 100", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("p50 пустой выборки = %d, ожидалось 0", got)
	}
}

// TestBuildSnapshot — сидированный store: экономика окна, перцентили из
// latency ok-вызовов, кэш-доля, streak > 5 → unavailable, сводка по
// источникам, доля confirmed.
func TestBuildSnapshot(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if err := st.SaveScan(ctx, &store.Scan{ID: "s1", SourceName: "ch", Profile: "deep", Status: "done", StartedAt: now}); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	vs := []verdict.Verdict{
		{ID: "v1", ScanID: "s1", Table: "t", Path: "c1", Label: "EMAIL", ReviewStatus: verdict.StatusPending, CreatedAt: now},
		{ID: "v2", ScanID: "s1", Table: "t", Path: "c2", Label: "PHONE", ReviewStatus: verdict.StatusPending, CreatedAt: now},
	}
	// 10 ok-вызовов latency 10..100 (p50=50, p95=100), 5 кэш-попаданий,
	// 6 ошибок подряд последними (unavailable).
	var calls []store.AgentCall
	for i := 0; i < 10; i++ {
		calls = append(calls, store.AgentCall{
			ID: "ok-" + string(rune('a'+i)), ScanID: "s1", VerdictID: "v1",
			AgentID: "zond-main", Model: "m", TokensIn: 10, TokensOut: 2,
			CostUSD: 0.001, LatencyMS: int64(10 * (i + 1)), Status: "ok", CreatedAt: now.Add(-time.Hour),
		})
	}
	for i := 0; i < 5; i++ {
		calls = append(calls, store.AgentCall{
			ID: "hit-" + string(rune('a'+i)), ScanID: "s1", VerdictID: "v2",
			AgentID: "zond-main", Model: "m", Status: "cache_hit", CreatedAt: now.Add(-time.Hour),
		})
	}
	for i := 0; i < 6; i++ {
		calls = append(calls, store.AgentCall{
			ID: "err-" + string(rune('a'+i)), ScanID: "s1", VerdictID: "v2",
			AgentID: "zond-main", Model: "m", Status: "error", CreatedAt: now,
		})
	}
	if err := st.SaveVerdictsWithCalls(ctx, vs, calls, nil); err != nil {
		t.Fatalf("SaveVerdictsWithCalls: %v", err)
	}
	if _, err := st.ApplyReview(ctx, "v1", store.ReviewConfirm, "", "sso:t", now); err != nil {
		t.Fatalf("ApplyReview: %v", err)
	}

	m := NewMeter()
	m.IncrScanFinished("done")
	snap, err := BuildSnapshot(ctx, st, m, 24*time.Hour)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	// Calls — ok+error (как CostRow), cache_hit отдельно.
	if snap.LLM.Calls != 16 || snap.LLM.Errors != 6 || snap.LLM.CacheHits != 5 {
		t.Errorf("llm calls/errors/cache = %d/%d/%d, ожидалось 16/6/5",
			snap.LLM.Calls, snap.LLM.Errors, snap.LLM.CacheHits)
	}
	if snap.LLM.CacheHitShare != 5.0/21.0 {
		t.Errorf("cache_hit_share = %v, ожидалось %v", snap.LLM.CacheHitShare, 5.0/21.0)
	}
	if snap.LLM.LatencyP50Ms != 50 || snap.LLM.LatencyP95Ms != 100 {
		t.Errorf("p50/p95 = %d/%d, ожидалось 50/100", snap.LLM.LatencyP50Ms, snap.LLM.LatencyP95Ms)
	}
	if !snap.LLM.Unavailable || snap.LLM.UnavailableStreak != 6 {
		t.Errorf("unavailable = %v/%d, ожидалось true/6", snap.LLM.Unavailable, snap.LLM.UnavailableStreak)
	}
	// LLMColumns — distinct вердикты с не-кэш вызовами: v1 (ok) и v2 (errors).
	if len(snap.Sources) != 1 || snap.Sources[0].Source != "ch" || snap.Sources[0].Pending != 1 || snap.Sources[0].LLMColumns != 2 {
		t.Errorf("sources: %+v", snap.Sources)
	}
	if snap.Review.ConfirmedShare != 1.0 || snap.Review.ReviewedTotal != 1 {
		t.Errorf("review: %+v", snap.Review)
	}
	if snap.Process.ScansByStatus["done"] != 1 {
		t.Errorf("process: %+v", snap.Process.ScansByStatus)
	}
}

// TestBuildSnapshotEmpty — пустой store: снимок без паник и делений на ноль.
func TestBuildSnapshotEmpty(t *testing.T) {
	st := openStore(t)
	snap, err := BuildSnapshot(context.Background(), st, NewMeter(), 0)
	if err != nil {
		t.Fatalf("BuildSnapshot: %v", err)
	}
	if snap.LLM.Calls != 0 || snap.LLM.Unavailable || len(snap.Sources) != 0 {
		t.Errorf("пустой снимок: %+v", snap)
	}
	if snap.Window != DefaultWindow.String() {
		t.Errorf("window = %s, ожидалось %s", snap.Window, DefaultWindow)
	}
}
