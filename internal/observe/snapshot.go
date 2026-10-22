// Снимок бизнес/технических метрик инстанса (blueprint п. 17): процесс
// (Meter) + окно агрегации из store (agent_calls/verdicts/review_events) +
// сводка последних прогонов по источникам. Источник — GET /api/v1/stats/metrics,
// expvar zond/store и дашборд /cost.
package observe

import (
	"context"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// DefaultWindow — окно агрегации по умолчанию (п. 17: технические метрики).
const DefaultWindow = 24 * time.Hour

// Snapshot — метрики инстанса для API/expvar/дашборда.
type Snapshot struct {
	GeneratedAt string          `json:"generated_at"` // RFC3339, UTC
	Window      string          `json:"window"`       // окно агрегации, напр. "24h"
	Process     Metrics         `json:"process"`
	LLM         LLMMetrics      `json:"llm"`
	Sources     []SourceMetrics `json:"sources"`
	Review      ReviewMetrics   `json:"review"`
}

// LLMMetrics — экономика и качество вызовов за окно (п. 17).
type LLMMetrics struct {
	Calls             int     `json:"calls"`
	Errors            int     `json:"errors"`
	CacheHits         int     `json:"cache_hits"`
	CacheHitShare     float64 `json:"cache_hit_share"` // cache_hits/(calls+cache_hits)
	TokensIn          int64   `json:"tokens_in"`
	TokensOut         int64   `json:"tokens_out"`
	CostUSD           float64 `json:"cost_usd"`
	LatencyP50Ms      int64   `json:"latency_p50_ms"`
	LatencyP95Ms      int64   `json:"latency_p95_ms"`
	UnavailableStreak int     `json:"unavailable_streak"` // последних подряд ошибок
	Unavailable       bool    `json:"unavailable"`        // streak > 5 (п. 17)
}

// SourceMetrics — сводка последнего прогона источника (п. 17).
type SourceMetrics struct {
	Source     string  `json:"source"`
	ScanID     string  `json:"scan_id"`
	Status     string  `json:"status"`
	Columns    int     `json:"columns"`
	LLMColumns int     `json:"llm_columns"`
	NoLLMShare float64 `json:"no_llm_share"`
	Pending    int     `json:"pending"`
}

// ReviewMetrics — петля обратной связи ревью (п. 17: доля confirmed).
type ReviewMetrics struct {
	Actions        map[string]int `json:"actions"`         // confirm/reject/relabel за окно
	ReviewedTotal  int            `json:"reviewed_total"`  // сумма действий
	ConfirmedShare float64        `json:"confirmed_share"` // confirm/reviewed_total
}

// BuildSnapshot собирает снимок: meter — процессные счётчики, st — store
// для оконных агрегатов; window — окно (по умолчанию DefaultWindow).
// Ошибки отдельных запросов не роняют снимок: секция остаётся нулевой
// (наблюдаемость не должна ломать выдачу).
func BuildSnapshot(ctx context.Context, st *store.Store, meter *Meter, window time.Duration) (*Snapshot, error) {
	if window <= 0 {
		window = DefaultWindow
	}
	if meter == nil {
		meter = Default
	}
	now := time.Now().UTC()
	snap := &Snapshot{
		GeneratedAt: now.Format(time.RFC3339),
		Window:      window.String(),
		Process:     meter.Snapshot(),
		Review:      ReviewMetrics{Actions: map[string]int{}},
	}
	if st == nil {
		return snap, nil
	}
	if w, err := st.LLMWindowStats(ctx, now.Add(-window)); err == nil {
		snap.LLM = LLMMetrics{
			Calls:        w.Calls,
			Errors:       w.Errors,
			CacheHits:    w.CacheHits,
			TokensIn:     w.TokensIn,
			TokensOut:    w.TokensOut,
			CostUSD:      w.CostUSD,
			LatencyP50Ms: percentile(w.Latencies, 0.50),
			LatencyP95Ms: percentile(w.Latencies, 0.95),
		}
		if w.Calls+w.CacheHits > 0 {
			snap.LLM.CacheHitShare = float64(w.CacheHits) / float64(w.Calls+w.CacheHits)
		}
	}
	if streak, _, err := st.LLMErrorStreak(ctx, 6); err == nil {
		snap.LLM.UnavailableStreak = streak
		snap.LLM.Unavailable = streak > 5
	}
	if ov, err := st.LatestScanOverviews(ctx); err == nil {
		for _, o := range ov {
			snap.Sources = append(snap.Sources, SourceMetrics(o))
		}
	}
	if acts, err := st.ReviewActionCounts(ctx, now.Add(-window)); err == nil {
		snap.Review.Actions = acts
		for _, n := range acts {
			snap.Review.ReviewedTotal += n
		}
		if snap.Review.ReviewedTotal > 0 {
			snap.Review.ConfirmedShare = float64(acts["confirm"]) / float64(snap.Review.ReviewedTotal)
		}
	}
	return snap, nil
}

// percentile — ближайший ранг: индекс ceil(q·n)−1 по возрастающей выборке
// (store отдаёт latency с ORDER BY); пустая выборка → 0.
func percentile(sorted []int64, q float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q*float64(len(sorted))+0.999999) - 1 // ceil(q·n)−1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
