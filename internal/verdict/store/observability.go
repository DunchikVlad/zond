// Наблюдаемость: агрегаты agent_calls/verdicts/scans для метрик (blueprint
// п. 17) и алертинга. Перцентили latency считает observe (store отдаёт
// отсортированную выборку); окно агрегации задаётся вызывающим.
package store

import (
	"context"
	"time"
)

// LLMWindow — агрегаты вызовов LLM за окно (п. 17): экономика, ошибки,
// кэш-попадания + отсортированные latency ok-вызовов (для p50/p95).
type LLMWindow struct {
	Calls     int     `json:"calls"`
	Errors    int     `json:"errors"`
	CacheHits int     `json:"cache_hits"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	Latencies []int64 `json:"-"` // latency_ms ok-вызовов, по возрастанию
}

// LLMWindowStats считает агрегаты agent_calls с created_at >= since.
func (s *Store) LLMWindowStats(ctx context.Context, since time.Time) (*LLMWindow, error) {
	w := &LLMWindow{Latencies: []int64{}}
	sinceStr := since.UTC().Format(time.RFC3339)
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE status IN ('ok','error')),
		       COUNT(*) FILTER (WHERE status = 'error'),
		       COUNT(*) FILTER (WHERE status = 'cache_hit'),
		       COALESCE(SUM(tokens_in)  FILTER (WHERE status = 'ok'), 0),
		       COALESCE(SUM(tokens_out) FILTER (WHERE status = 'ok'), 0),
		       COALESCE(SUM(cost_usd)   FILTER (WHERE status = 'ok'), 0)
		FROM agent_calls WHERE created_at >= ?`, sinceStr).Scan(
		&w.Calls, &w.Errors, &w.CacheHits, &w.TokensIn, &w.TokensOut, &w.CostUSD)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT latency_ms FROM agent_calls
		WHERE created_at >= ? AND status = 'ok' ORDER BY latency_ms`, sinceStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		w.Latencies = append(w.Latencies, v)
	}
	return w, rows.Err()
}

// LLMErrorStreak — число последних подряд вызовов со статусом error
// (событие llm_unavailable, п. 17 «>5 подряд»). Проверяется до max последних
// вызовов; 0 — последний вызов не ошибка или вызовов нет.
func (s *Store) LLMErrorStreak(ctx context.Context, max int) (int, error) {
	if max <= 0 {
		max = 6
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT status FROM agent_calls ORDER BY created_at DESC, rowid DESC LIMIT ?`, max)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var streak int
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return 0, err
		}
		if status != "error" {
			break
		}
		streak++
	}
	return streak, rows.Err()
}

// SourceOverview — сводка по последнему прогону источника (п. 17: дашборды
// и алертинг R9). NoLLMShare — доля колонок без реального LLM-вызова.
type SourceOverview struct {
	Source     string  `json:"source"`
	ScanID     string  `json:"scan_id"`
	Status     string  `json:"status"`
	Columns    int     `json:"columns"`
	LLMColumns int     `json:"llm_columns"`
	NoLLMShare float64 `json:"no_llm_share"`
	Pending    int     `json:"pending"`
}

// LatestScanOverviews возвращает сводку по последнему прогону каждого
// источника (по MAX(started_at) — формат RFC3339, лексикографический максимум
// корректен). Источники без прогонов не возвращаются.
func (s *Store) LatestScanOverviews(ctx context.Context) ([]SourceOverview, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.source_name, s.status
		FROM scans s
		JOIN (SELECT source_name, MAX(started_at) AS m FROM scans GROUP BY source_name) latest
		  ON latest.source_name = s.source_name AND latest.m = s.started_at
		ORDER BY s.source_name`)
	if err != nil {
		return nil, err
	}
	var out []SourceOverview
	ids := []string{}
	for rows.Next() {
		var o SourceOverview
		if err := rows.Scan(&o.ScanID, &o.Source, &o.Status); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, o)
		ids = append(ids, o.ScanID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if len(ids) == 0 {
		return out, nil
	}
	ph := placeholders(len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	cols := map[string]int{}
	pend := map[string]int{}
	llm := map[string]int{}
	r1, err := s.db.QueryContext(ctx,
		`SELECT scan_id, COUNT(*) FROM verdicts WHERE scan_id IN (`+ph+`) GROUP BY scan_id`, args...)
	if err != nil {
		return nil, err
	}
	for r1.Next() {
		var id string
		var n int
		if err := r1.Scan(&id, &n); err != nil {
			r1.Close()
			return nil, err
		}
		cols[id] = n
	}
	r1.Close()
	r2, err := s.db.QueryContext(ctx,
		`SELECT scan_id, COUNT(*) FROM verdicts WHERE scan_id IN (`+ph+`) AND review_status = 'pending' GROUP BY scan_id`, args...)
	if err != nil {
		return nil, err
	}
	for r2.Next() {
		var id string
		var n int
		if err := r2.Scan(&id, &n); err != nil {
			r2.Close()
			return nil, err
		}
		pend[id] = n
	}
	r2.Close()
	r3, err := s.db.QueryContext(ctx,
		`SELECT scan_id, COUNT(DISTINCT verdict_id) FROM agent_calls
		 WHERE scan_id IN (`+ph+`) AND status != 'cache_hit' GROUP BY scan_id`, args...)
	if err != nil {
		return nil, err
	}
	for r3.Next() {
		var id string
		var n int
		if err := r3.Scan(&id, &n); err != nil {
			r3.Close()
			return nil, err
		}
		llm[id] = n
	}
	r3.Close()
	for i := range out {
		out[i].Columns = cols[out[i].ScanID]
		out[i].Pending = pend[out[i].ScanID]
		out[i].LLMColumns = llm[out[i].ScanID]
		if out[i].Columns > 0 {
			out[i].NoLLMShare = float64(out[i].Columns-out[i].LLMColumns) / float64(out[i].Columns)
		}
	}
	return out, nil
}

// ReviewActionCounts — число действий ревью (confirm/reject/relabel) за окно
// (п. 17: доля pending, переведённых в confirmed — качество ансамбля).
func (s *Store) ReviewActionCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT action, COUNT(*) FROM review_events WHERE ts >= ?
		GROUP BY action`, since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var action string
		var n int
		if err := rows.Scan(&action, &n); err != nil {
			return nil, err
		}
		out[action] = n
	}
	return out, rows.Err()
}
