// Package observe — метрики, наблюдаемость и алертинг (blueprint п. 17;
// S6в). Три контура:
//
//  1. Meter — атомарные счётчики процесса: пишет scanengine в точках учёта,
//     читается expvar-экспозицией /debug/vars и алертингом;
//  2. Snapshot — бизнес/технические агрегаты из store (scans.stats_json,
//     agent_calls): доля решённого без LLM, p50/p95 latency, доля
//     кэш-попаданий, pending→confirmed (S6в-2);
//  3. Evaluator — встроенный алертинг (S6в-3): budget_exceeded, рост
//     pending (R9), серия llm_unavailable, разрыв hash-chain аудита;
//     события — в audit-лог и опциональный webhook.
package observe

import (
	"encoding/json"
	"expvar"
	"math"
	"sync"
	"sync/atomic"
)

// Meter — атомарные счётчики процесса (п. 17 «технические метрики»).
// Все поля — atomic.Int64; чтение и запись без внешней синхронизации
// (движок пишет из воркеров скана).
type Meter struct {
	scansStarted      atomic.Int64
	scansFinished     atomic.Int64
	byStatus          sync.Map     // scan status → *atomic.Int64
	llmCalls          atomic.Int64 // ok-вызовы LLM (не кэш)
	llmErrors         atomic.Int64 // вызовы LLM со статусом error
	cacheHits         atomic.Int64 // вердикты из кэша (п. 10.5)
	clusterPropagated atomic.Int64 // вердикты из кластеров (п. 7.6)
	tokensIn          atomic.Int64
	tokensOut         atomic.Int64
	costMicros        atomic.Int64 // $ × 1e6 (округление 6 знаков, как у движка)
	verdicts          atomic.Int64
}

// Default — счётчики процесса. Движок инкрементирует их напрямую; чтение —
// через Snapshot/DefaultSnapshot.
var Default = NewMeter()

// NewMeter пустой счётчик (тесты изолируются от глобального Default).
func NewMeter() *Meter { return &Meter{} }

// IncrScanStarted — прогон стартовал (п. 17).
func (m *Meter) IncrScanStarted() { m.scansStarted.Add(1) }

// IncrScanFinished — прогон завершился со статусом (done/partial/interrupted/
// budget_exceeded/failed — см. scanengine.finish).
func (m *Meter) IncrScanFinished(status string) {
	m.scansFinished.Add(1)
	c, _ := m.byStatus.LoadOrStore(status, new(atomic.Int64))
	c.(*atomic.Int64).Add(1)
}

// IncrLLMCall — ok-вызов LLM (не кэш; п. 10.6).
func (m *Meter) IncrLLMCall() { m.llmCalls.Add(1) }

// IncrLLMError — вызов LLM завершился ошибкой (п. 10.6).
func (m *Meter) IncrLLMError() { m.llmErrors.Add(1) }

// IncrCacheHit — вердикт из кэша (п. 10.5).
func (m *Meter) IncrCacheHit() { m.cacheHits.Add(1) }

// IncrClusterPropagated — вердикт распространён из кластера (п. 7.6).
func (m *Meter) IncrClusterPropagated() { m.clusterPropagated.Add(1) }

// AddTokens — токены ok-вызовов (п. 17).
func (m *Meter) AddTokens(in, out int) {
	m.tokensIn.Add(int64(in))
	m.tokensOut.Add(int64(out))
}

// AddCostUSD — стоимость ok-вызовов, $ (п. 17; округление как у движка).
func (m *Meter) AddCostUSD(usd float64) {
	m.costMicros.Add(int64(math.Round(usd * 1e6)))
}

// AddVerdicts — колонок с вердиктами за прогоны.
func (m *Meter) AddVerdicts(n int) { m.verdicts.Add(int64(n)) }

// Metrics — снимок счётчиков (JSON для /debug/vars и алертинга).
type Metrics struct {
	ScansStarted      int64            `json:"scans_started"`
	ScansFinished     int64            `json:"scans_finished"`
	ScansByStatus     map[string]int64 `json:"scans_by_status"`
	LLMCalls          int64            `json:"llm_calls"`
	LLMErrors         int64            `json:"llm_errors"`
	LLMCacheHits      int64            `json:"llm_cache_hits"`
	ClusterPropagated int64            `json:"cluster_propagated"`
	TokensIn          int64            `json:"tokens_in"`
	TokensOut         int64            `json:"tokens_out"`
	CostUSD           float64          `json:"cost_usd"`
	Verdicts          int64            `json:"verdicts"`
}

// Snapshot возвращает копию счётчиков (по статусам — только реально
// встречавшиеся).
func (m *Meter) Snapshot() Metrics {
	snap := Metrics{
		ScansStarted:      m.scansStarted.Load(),
		ScansFinished:     m.scansFinished.Load(),
		ScansByStatus:     map[string]int64{},
		LLMCalls:          m.llmCalls.Load(),
		LLMErrors:         m.llmErrors.Load(),
		LLMCacheHits:      m.cacheHits.Load(),
		ClusterPropagated: m.clusterPropagated.Load(),
		TokensIn:          m.tokensIn.Load(),
		TokensOut:         m.tokensOut.Load(),
		CostUSD:           float64(m.costMicros.Load()) / 1e6,
		Verdicts:          m.verdicts.Load(),
	}
	m.byStatus.Range(func(k, v any) bool {
		snap.ScansByStatus[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return snap
}

// String — JSON-снимок (реализация expvar.Var через Func-публикацию).
func (m *Meter) String() string {
	b, _ := json.Marshal(m.Snapshot())
	return string(b)
}

var publishOnce sync.Once

// PublishExpvar публикует Default в expvar-реестр как "zond/process"
// (идемпотентно; вызывается из wiring'а serve/cmd). Повторные вызовы —
// no-op, чтобы тесты не конфликтовали за глобальный реестр.
func PublishExpvar() {
	publishOnce.Do(func() {
		expvar.Publish("zond/process", expvar.Func(func() any { return Default.Snapshot() }))
	})
}
