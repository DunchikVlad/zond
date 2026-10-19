// Агрегация экономики LLM-вызовов для REST API (blueprint п. 11.2
// GET /api/v1/stats/cost, п. 17): токены/стоимость по агентам и моделям,
// доля решённого без LLM.
package store

import (
	"context"
)

// CostRow — агрегат по паре (agent_id, model) за прогон (п. 11.2, п. 17).
type CostRow struct {
	AgentID    string  `json:"agent_id"`
	Model      string  `json:"model"`
	Calls      int     `json:"calls"`      // реальные сетевые вызовы (status='ok' + 'error')
	CacheHits  int     `json:"cache_hits"` // попадания в кэш вердиктов (п. 10.5)
	Errors     int     `json:"errors"`     // вызовы с status='error' (п. 10.6)
	TokensIn   int     `json:"tokens_in"`
	TokensOut  int     `json:"tokens_out"`
	CostUSD    float64 `json:"cost_usd"`
	LatencyAvg float64 `json:"latency_avg_ms"`
}

// CostStats — экономика прогона: разрез по агентам/моделям + итоги + доля
// колонок, решённых без LLM (цель ≥70%, п. 17).
type CostStats struct {
	ScanID     string    `json:"scan_id"`
	ByAgent    []CostRow `json:"by_agent"`
	Calls      int       `json:"calls"`
	CacheHits  int       `json:"cache_hits"`
	TokensIn   int       `json:"tokens_in"`
	TokensOut  int       `json:"tokens_out"`
	CostUSD    float64   `json:"cost_usd"`
	Columns    int       `json:"columns"`      // всего вердиктов прогона
	LLMColumns int       `json:"llm_columns"`  // вердикты слоёв llm/ensemble с реальным вызовом…
	NoLLMShare float64   `json:"no_llm_share"` // 1 - llm_columns/columns (п. 17)
}

// ScanCostStats считает экономику прогона по agent_calls + verdicts.
func (s *Store) ScanCostStats(ctx context.Context, scanID string) (*CostStats, error) {
	st := &CostStats{ScanID: scanID, ByAgent: []CostRow{}}
	rows, err := s.db.QueryContext(ctx, `
		SELECT agent_id, model,
		       COUNT(*) FILTER (WHERE status IN ('ok','error')) AS calls,
		       COUNT(*) FILTER (WHERE status = 'cache_hit')      AS cache_hits,
		       COUNT(*) FILTER (WHERE status = 'error')          AS errors,
		       COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
		       COALESCE(SUM(cost_usd), 0), COALESCE(AVG(latency_ms), 0)
		FROM agent_calls WHERE scan_id = ?
		GROUP BY agent_id, model ORDER BY agent_id, model`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r CostRow
		if err := rows.Scan(&r.AgentID, &r.Model, &r.Calls, &r.CacheHits, &r.Errors,
			&r.TokensIn, &r.TokensOut, &r.CostUSD, &r.LatencyAvg); err != nil {
			return nil, err
		}
		st.ByAgent = append(st.ByAgent, r)
		st.Calls += r.Calls
		st.CacheHits += r.CacheHits
		st.TokensIn += r.TokensIn
		st.TokensOut += r.TokensOut
		st.CostUSD += r.CostUSD
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Доля решённого без LLM (п. 17): слои meta/rules + кэш/кластер не тратят
	// вызовов; llm-столбцы — вердикты, у которых есть не-кэш вызов.
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM verdicts WHERE scan_id = ?`, scanID).Scan(&st.Columns); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT verdict_id) FROM agent_calls
		WHERE scan_id = ? AND status != 'cache_hit'`, scanID).Scan(&st.LLMColumns); err != nil {
		return nil, err
	}
	if st.Columns > 0 {
		st.NoLLMShare = float64(st.Columns-st.LLMColumns) / float64(st.Columns)
	}
	return st, nil
}
