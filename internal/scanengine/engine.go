// Package scanengine — оркестрация скана: таблицы → сэмпл → каскад слоёв 0–1 →
// вердикты в store, чекпоинт после каждой таблицы (blueprint п. 7, п. 13).
// Этап 1: слои 0–1 + упрощённый ensemble; LLM-слой — этап 4; resume — позже (п. 13).
package scanengine

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/agentproxy/mask"
	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
	"github.com/DunchikVlad/zond/internal/analyze/cluster"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/fingerprint"
	"github.com/DunchikVlad/zond/internal/observe"
	"github.com/DunchikVlad/zond/internal/sampler"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Config — параметры движка, получаемые из detectors.yaml + taxonomy.yaml.
type Config struct {
	TauAccept        float64
	TauReview        float64
	Weights          map[string]float64 // meta | rules | llm (ensemble.weights)
	GrayBand         [2]float64         // confidence_band агента (серая зона)
	SampleMode       connector.SampleMode
	SampleValue      float64
	MaxRows          int64
	MaxStringChars   int
	Dedup            bool
	MinValuesForLLM  int // сэмпл меньше — LLM не вызывается (п. 7)
	TaxonomyVersion  string
	DetectorsVersion string
	Sensitivity      map[verdict.Label]verdict.Sensitivity
	TaxonomyLabels   []string // enum лейблов для промпта LLM

	// Инкремент 4б: кэш вердиктов (п. 10.5) и кластеризация (п. 7.6).
	CacheScope        string // "agent_id|model" — идентичность агента в ключе кэша; "" → кэш выключен
	Clustering        bool   // кластеризация колонок до слоя 2
	ClusterSimilarity float64
	ClusterMaxSize    int

	// Инкремент 4в: budget-стоп LLM-слоя (blueprint п. 10.4).
	CostScanLimitUSD float64 // суммарная стоимость вызовов скана; >0 — при превышении LLM-вызовы прекращаются

	// Инкремент 5а: аудит действий (ADR-0013, п. 14.2) — автор событий
	// скана ("cli" по умолчанию; в этапе 5 — sso:<subject>/token:<id>).
	Actor string

	// Инкремент 8: resource governance (blueprint п. 13.2). Breaker — общий
	// circuit breaker процесса (nil — выключен: unit-тесты без пауз).
	Breaker *Breaker
	// ResumeFrom — id прогона (partial/interrupted), чьи done-таблицы
	// пропускаются (--resume, п. 13.2).
	ResumeFrom string
}

// retryBackoff — паузы между повторами retryable-таблицы (п. 13.2):
// retry только на retryable-ошибки драйвера, всего до 3 попыток.
var retryBackoff = []time.Duration{250 * time.Millisecond, time.Second}

// LLMIdentity — идентичность агента для учётных записей agent_calls
// (blueprint п. 10.6): кто и какая моделя выполнила вызов.
type LLMIdentity struct {
	AgentID string
	Model   string
}

// LLMClassifier — минимальный интерфейс LLM-слоя для движка (п. 7).
// Реализуется agentproxy.Proxy; в тестах — fake. nil → слой 2 отключён.
type LLMClassifier interface {
	Classify(ctx context.Context, nativeType string, values []string) (*agentproxy.ClassifyResult, error)
	Verify(ctx context.Context, candidate, nativeType string, values []string) (*agentproxy.VerifyResult, error)
}

// Engine — движок сканирования одного источника.
type Engine struct {
	st        *store.Store
	meta      *meta.Analyzer
	recs      []rules.Recognizer
	llm       LLMClassifier // nil → слой 2 (LLM) отключён
	llmID     LLMIdentity   // идентичность для agent_calls (п. 10.6)
	cfg       Config
	nowFn     func() time.Time
	clusterer *cluster.Clusterer // на скан (п. 7.6); nil — кластеризация выключена
	stats     scanStats          // счётчики экономики текущего прогона

	// Инкремент 4в: буфер учётных записей вызовов текущей таблицы (п. 10.6)
	// и накопленная стоимость/бюджет (п. 10.4). Сбрасываются после коммита
	// таблицы вместе с вердиктами (атомарность п. 13).
	calls          []store.AgentCall
	cost           float64
	budgetExceeded bool
	prices         map[string]modelPrice // ленивый кэш прайс-листа model_prices

	// Инкремент 5а: буфер аудит-событий таблицы (ADR-0013): пишется в той же
	// транзакции, что вердикты и вызовы (п. 13/14.2). 1:1 с calls (п. 14.2:
	// каждый вызов агента — событие со ссылкой на agent_calls).
	events []audit.Event
}

// modelPrice — цена модели за 1M токенов (п. 11.1) из кэша движка.
type modelPrice struct {
	in  float64
	out float64
}

// scanStats — счётчики экономики сканирования (blueprint п. 17).
type scanStats struct {
	llmCalls   int // реальные вызовы LLM
	cacheHits  int // вердикты из кэша (п. 10.5)
	propagated int // вердикты из кластера (п. 7.6)
	llmErrors  int // вызовы LLM, завершившиеся ошибкой (п. 10.6: status='error')
	tokensIn   int // суммарные входящие токены ok-вызовов (п. 17)
	tokensOut  int // суммарные исходящие токены ok-вызовов (п. 17)
}

// New собирает движок: recognizer'ы слоя 1 по умолчанию (rules.Default).
func New(st *store.Store, m *meta.Analyzer, cfg Config) *Engine {
	return &Engine{st: st, meta: m, recs: rules.Default(), cfg: cfg, nowFn: time.Now}
}

// SetLLM подключает LLM-слой (этап 4): серый коридор + эскалация (п. 7).
// id — идентичность агента для учёта вызовов (п. 10.6).
func (e *Engine) SetLLM(llm LLMClassifier, id LLMIdentity) {
	e.llm = llm
	e.llmID = id
}

// Report — итог прогона (консольный отчёт этапа 1).
type Report struct {
	ScanID            string
	Source            string
	Profile           string
	Status            string
	StartedAt         time.Time
	FinishedAt        time.Time
	TablesTotal       int
	TablesDone        int
	TablesFailed      int
	Skipped           int    // таблицы, пропущенные по чекпоинтам resume (п. 13.2)
	ResumeFrom        string // id прогона-чекпоинта (--resume; "" — полный прогон)
	BreakerTripped    bool   // circuit breaker остановил прогон (п. 13.2)
	Verdicts          int
	Pending           int
	ByLabel           map[string]int
	ByLayer           map[string]int
	ByStatus          map[string]int
	LLMCalls          int     // экономика: реальные вызовы LLM (п. 17)
	CacheHits         int     // вердикты из кэша (п. 10.5)
	ClusterPropagated int     // вердикты из кластеров (п. 7.6)
	LLMErrors         int     // вызовы LLM со статусом error (п. 10.6)
	TokensIn          int     // суммарные входящие токены ok-вызовов (п. 17)
	TokensOut         int     // суммарные исходящие токены ok-вызовов (п. 17)
	CostUSD           float64 // стоимость вызовов скана по прайс-листу (п. 11.1)
	Errors            []string
}

// Text печатает человекочитаемый отчёт.
func (r *Report) Text(w io.Writer) {
	fmt.Fprintf(w, "\n=== Скан %s — источник %s (профиль %s) ===\n", r.ScanID, r.Source, r.Profile)
	fmt.Fprintf(w, "Статус: %s   Длительность: %s\n", r.Status, r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "Таблицы: %d всего, %d обработано, %d с ошибками\n", r.TablesTotal, r.TablesDone, r.TablesFailed)
	if r.ResumeFrom != "" {
		fmt.Fprintf(w, "Resume: пропущено %d таблиц (чекпоинты прогона %s)\n", r.Skipped, r.ResumeFrom)
	}
	if r.BreakerTripped {
		fmt.Fprintln(w, "Circuit breaker: источник взят на паузу (5 мин, п. 13.2) — догнать можно флагом -resume")
	}
	fmt.Fprintf(w, "Вердикты: %d (ожидают ревью: %d)\n", r.Verdicts, r.Pending)
	fmt.Fprintf(w, "По слоям: %s\n", joinSorted(r.ByLayer))
	fmt.Fprintf(w, "По лейблам: %s\n", joinSorted(r.ByLabel))
	if r.LLMCalls+r.CacheHits+r.ClusterPropagated > 0 {
		fmt.Fprintf(w, "Экономика: LLM-вызовов %d, из кэша %d, из кластеров %d, $%0.4f (токены in/out %d/%d)\n",
			r.LLMCalls, r.CacheHits, r.ClusterPropagated, r.CostUSD, r.TokensIn, r.TokensOut)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "Ошибки таблиц:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
}

func joinSorted(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

// Scan выполняет полный прогон по источнику (blueprint п. 13):
// недоступная таблица помечается failed и не роняет скан (п. 6).
func (e *Engine) Scan(ctx context.Context, conn connector.Connector, sourceName, profile string) (*Report, error) {
	return e.ScanWithID(ctx, conn, sourceName, profile, newScanID(e.nowFn()))
}

// ScanWithID — Scan с заранее заданным идентификатором прогона. Нужен
// REST API (инкремент 5б, blueprint п. 11.2): POST /scans обязан вернуть
// scan_id до завершения асинхронного прогона. CLI использует Scan.
func (e *Engine) ScanWithID(ctx context.Context, conn connector.Connector, sourceName, profile, scanID string) (*Report, error) {
	rep := &Report{
		ScanID:    scanID,
		Source:    sourceName,
		Profile:   profile,
		Status:    "running",
		StartedAt: e.nowFn(),
		ByLabel:   map[string]int{},
		ByLayer:   map[string]int{},
		ByStatus:  map[string]int{},
	}
	// Circuit breaker (п. 13.2): источник на паузе — прогон не начинается
	// (строка scans не создаётся; до конца паузы — отказ с указанием until).
	if e.cfg.Breaker != nil {
		if err := e.cfg.Breaker.PausedErr(sourceName, e.nowFn()); err != nil {
			return nil, err
		}
	}
	if err := e.st.SaveScan(ctx, &store.Scan{
		ID: scanID, SourceName: sourceName, Profile: profile,
		Status: "running", StartedAt: rep.StartedAt,
	}); err != nil {
		return nil, fmt.Errorf("создание прогона: %w", err)
	}
	observe.Default.IncrScanStarted() // п. 17: счётчик процесса
	// Аудит старта скана (ADR-0013, п. 14.2): запись обязательна — ошибка
	// аудита отменяет скан (действие без аудита не считается совершённым).
	startDetails := map[string]any{"source": sourceName, "profile": profile}
	if e.cfg.ResumeFrom != "" {
		startDetails["resume_from"] = e.cfg.ResumeFrom
	}
	if err := e.st.AppendAudit(ctx, []audit.Event{e.scanEvent(scanID, "scan_start", startDetails)}); err != nil {
		_ = e.st.FinishScan(ctx, scanID, "failed", "{}", e.nowFn())
		return nil, fmt.Errorf("аудит старта скана: %w", err)
	}
	if e.cfg.Clustering {
		e.clusterer = cluster.New(e.cfg.ClusterSimilarity, e.cfg.ClusterMaxSize)
	} else {
		e.clusterer = nil
	}
	e.stats = scanStats{}
	e.calls = nil
	e.cost = 0
	e.budgetExceeded = false

	tables, err := conn.ListTables(ctx)
	if err != nil {
		// аудит finish на пути уже падающего скана — best effort (п. 14.2)
		_ = e.finish(ctx, rep, "failed")
		return rep, fmt.Errorf("list tables: %w", err)
	}
	rep.TablesTotal = len(tables)

	// Resume (п. 13.2): пропускаем таблицы, уже done в чекпоинт-прогоне.
	if e.cfg.ResumeFrom != "" {
		done, err := e.st.DoneTables(ctx, e.cfg.ResumeFrom)
		if err != nil {
			_ = e.finish(ctx, rep, "failed")
			return rep, fmt.Errorf("resume: чекпоинты прогона %s: %w", e.cfg.ResumeFrom, err)
		}
		remaining := tables[:0]
		for _, t := range tables {
			if !done[t.Name] {
				remaining = append(remaining, t)
			}
		}
		rep.Skipped = len(tables) - len(remaining)
		rep.ResumeFrom = e.cfg.ResumeFrom
		tables = remaining
	}

	interrupted := false
	consecutiveOverload := 0
	for _, t := range tables {
		// Мягкая остановка (п. 11.2 stop, п. 13): отмена ctx между таблицами —
		// прогон фиксируется interrupted с чекпоинтами обработанных таблиц.
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		if err := e.scanTableRetry(ctx, conn, scanID, t, rep); err != nil {
			// ошибка уже записана в scan_tables (с причиной); продолжаем прочие
			rep.TablesFailed++
			if connector.ClassifyFailure(err) == connector.ReasonOverload {
				consecutiveOverload++
			} else {
				consecutiveOverload = 0
			}
			// Circuit breaker (п. 13.2): серия overload-ошибок → пауза источника.
			if e.cfg.Breaker != nil && consecutiveOverload >= breakerConsecutiveFails {
				until := e.cfg.Breaker.Trip(sourceName, e.nowFn(), breakerPause)
				rep.BreakerTripped = true
				// аудит паузы (п. 14.2): best effort — прогон уже падает.
				_ = e.st.AppendAudit(context.WithoutCancel(ctx), []audit.Event{e.scanEvent(scanID, "source_paused", map[string]any{
					"source": sourceName, "consecutive_overload_failures": consecutiveOverload,
					"pause_min":    breakerPause.Minutes(),
					"paused_until": until.UTC().Format(time.RFC3339),
				})})
				break
			}
		} else {
			rep.TablesDone++
			consecutiveOverload = 0
		}
	}

	status := "done"
	if rep.TablesFailed > 0 {
		status = "partial" // в т.ч. по circuit breaker (п. 13.2) и обычные ошибки
	}
	if interrupted {
		status = "interrupted" // stop приоритетнее done/partial
	}
	if e.budgetExceeded {
		status = "budget_exceeded" // budget-стоп приоритетнее done/partial (п. 10.4)
	}
	rep.LLMCalls = e.stats.llmCalls
	rep.CacheHits = e.stats.cacheHits
	rep.ClusterPropagated = e.stats.propagated
	rep.LLMErrors = e.stats.llmErrors
	rep.TokensIn = e.stats.tokensIn
	rep.TokensOut = e.stats.tokensOut
	rep.CostUSD = e.cost
	// Финализация (агрегаты, stats_json, аудит scan_finish) идёт даже при
	// отменённом ctx — WithoutCancel отвязывает от отмены, иначе interrupted-
	// прогон останется «вечным» running (п. 13, п. 11.2 stop).
	fin := context.WithoutCancel(ctx)
	if err := e.aggregate(fin, rep); err != nil {
		return rep, err
	}
	if err := e.finish(fin, rep, status); err != nil {
		return rep, err
	}
	return rep, nil
}

// finish фиксирует завершение прогона: статус + stats_json + аудит scan_finish
// (ADR-0013, п. 14.2). Ошибка аудита возвращается — вызывающий решает
// (на основном пути скан считается несостоявшимся, код возврата ненулевой).
func (e *Engine) finish(ctx context.Context, rep *Report, status string) error {
	rep.Status = status
	rep.FinishedAt = e.nowFn()
	observe.Default.IncrScanFinished(status) // п. 17
	stats, _ := json.Marshal(map[string]any{
		"tables_total": rep.TablesTotal, "tables_done": rep.TablesDone,
		"tables_failed": rep.TablesFailed, "verdicts": rep.Verdicts,
		"by_layer": rep.ByLayer, "by_label": rep.ByLabel,
		"llm_calls": rep.LLMCalls, "cache_hits": rep.CacheHits,
		"cluster_propagated": rep.ClusterPropagated,
		"llm_errors":         rep.LLMErrors, "tokens_in": rep.TokensIn, "tokens_out": rep.TokensOut,
		"cost_usd": rep.CostUSD,
		// Инкремент 8 (п. 13.2): следы resume и circuit breaker.
		"tables_skipped": rep.Skipped, "resume_from": rep.ResumeFrom,
		"breaker_tripped": rep.BreakerTripped,
	})
	_ = e.st.FinishScan(ctx, rep.ScanID, status, string(stats), rep.FinishedAt)
	return e.st.AppendAudit(ctx, []audit.Event{e.scanEvent(rep.ScanID, "scan_finish", map[string]any{
		"status": status, "duration_s": rep.FinishedAt.Sub(rep.StartedAt).Seconds(),
		"tables_total": rep.TablesTotal, "tables_done": rep.TablesDone,
		"tables_failed": rep.TablesFailed, "verdicts": rep.Verdicts,
		"pending": rep.Pending, "llm_calls": rep.LLMCalls, "cache_hits": rep.CacheHits,
		"cluster_propagated": rep.ClusterPropagated, "llm_errors": rep.LLMErrors,
		"tokens_in": rep.TokensIn, "tokens_out": rep.TokensOut, "cost_usd": rep.CostUSD,
	})})
}

// scanEvent собирает аудит-событие жизненного цикла скана (actor из Config).
func (e *Engine) scanEvent(scanID, action string, details map[string]any) audit.Event {
	return audit.Event{
		Actor: e.actor(), Category: audit.CatScan, Action: action,
		Target: "scan:" + scanID, Details: details, TS: e.nowFn(),
	}
}

// actor — автор аудит-событий (п. 14.2): CLI до появления SSO/API-токенов.
func (e *Engine) actor() string {
	if e.cfg.Actor != "" {
		return e.cfg.Actor
	}
	return "cli"
}

func (e *Engine) aggregate(ctx context.Context, rep *Report) error {
	sum, err := e.st.VerdictSummary(ctx, rep.ScanID)
	if err != nil {
		return err
	}
	rep.Verdicts = sum.Total
	rep.Pending = sum.ByStatus["pending"]
	rep.ByLabel = sum.ByLabel
	rep.ByLayer = sum.ByLayer
	rep.ByStatus = sum.ByStatus
	failed, err := e.st.FailedTables(ctx, rep.ScanID)
	if err != nil {
		return err
	}
	rep.Errors = failed
	observe.Default.AddVerdicts(rep.Verdicts) // п. 17
	return nil
}

// scanTableRetry оборачивает scanTable повторами (blueprint п. 13.2):
// retry — только на retryable-ошибки драйвера (перегрузка, таймаут,
// потеря лидерства), всего до 3 попыток с нарастающей паузой; прочие
// ошибки сразу фиксируют таблицу failed.
func (e *Engine) scanTableRetry(ctx context.Context, conn connector.Connector, scanID string, t connector.TableRef, rep *Report) error {
	for attempt := 0; ; attempt++ {
		err := e.scanTable(ctx, conn, scanID, t, rep)
		if err == nil || !connector.IsRetryable(err) || attempt >= len(retryBackoff) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retryBackoff[attempt]):
		}
	}
}

func (e *Engine) scanTable(ctx context.Context, conn connector.Connector, scanID string, t connector.TableRef, rep *Report) error {
	e.takeCalls() // сброс буфера: вызовы failed-таблицы не должны попасть в чужой коммит (п. 13)
	e.takeEvents()
	cols, err := conn.GetSchema(ctx, t)
	if err != nil {
		_ = e.st.MarkTable(ctx, scanID, t.Name, 0, "failed", err.Error(), string(connector.ClassifyFailure(err)))
		return err
	}
	var rowCount int64
	if n, err := conn.CountRows(ctx, t); err == nil {
		rowCount = n
	}
	vs := make([]verdict.Verdict, 0, len(cols))
	for _, col := range cols {
		v, err := e.classifyColumn(ctx, conn, scanID, t, col)
		if err != nil {
			// обрыв стрима сэмпла → таблица failed, чекпоинт (п. 6)
			_ = e.st.MarkTable(ctx, scanID, t.Name, rowCount, "failed", err.Error(), string(connector.ClassifyFailure(err)))
			return err
		}
		vs = append(vs, v)
	}
	// вердикты, учётные записи вызовов и аудит таблицы — одна транзакция
	// (п. 13: либо всё, либо откат; ADR-0013: действие без аудита не совершено)
	if err := e.st.SaveVerdictsWithCalls(ctx, vs, e.takeCalls(), e.takeEvents()); err != nil {
		_ = e.st.MarkTable(ctx, scanID, t.Name, rowCount, "failed", err.Error(), string(connector.ClassifyFailure(err)))
		return err
	}
	return e.st.MarkTable(ctx, scanID, t.Name, rowCount, "done", "", "")
}

func (e *Engine) classifyColumn(ctx context.Context, conn connector.Connector, scanID string, t connector.TableRef, col connector.Column) (verdict.Verdict, error) {
	seq, err := conn.Sample(ctx, connector.SampleSpec{
		Table:   t,
		Mode:    e.cfg.SampleMode,
		Value:   e.cfg.SampleValue,
		Columns: []string{col.Name},
		MaxRows: e.cfg.MaxRows,
	})
	if err != nil {
		return verdict.Verdict{}, err
	}
	pool, err := sampler.Build(seq, col.Name, sampler.Options{
		MaxRows:        e.cfg.MaxRows,
		MaxStringChars: e.cfg.MaxStringChars,
		Dedup:          e.cfg.Dedup,
	})
	if err != nil {
		return verdict.Verdict{}, err
	}
	return e.verdict(ctx, scanID, t, col, pool), nil
}

// verdict собирает вердикт колонки: слой 0 (имя) + слой 1 (rules) + слой 2 (LLM,
// серый коридор) → ensemble (п. 7).
func (e *Engine) verdict(ctx context.Context, scanID string, t connector.TableRef, col connector.Column, pool *sampler.Pool) verdict.Verdict {
	sum := sha1.Sum([]byte(scanID + "|" + t.Name + "|" + col.Name)) // п. 5.4
	v := verdict.Verdict{
		ID:               hex.EncodeToString(sum[:]),
		ScanID:           scanID,
		Table:            t.Name,
		Path:             col.Name,
		NativeType:       col.NativeType,
		SampleSize:       len(pool.Values),
		TaxonomyVersion:  e.cfg.TaxonomyVersion,
		DetectorsVersion: e.cfg.DetectorsVersion,
		Sensitivity:      e.cfg.Sensitivity[verdict.Label("UNKNOWN")],
		CreatedAt:        e.nowFn(),
	}

	cands := make([]ensemble.Candidate, 0, 4)
	if e.meta != nil {
		if l, c, ok := e.meta.ByName(col.Name); ok {
			cands = append(cands, ensemble.Candidate{Label: l, Confidence: c, Layer: verdict.LayerMeta})
		}
	}
	matches := rules.Analyze(pool.Values, e.recs...)
	evRules := map[string]any{}
	for _, m := range matches {
		cands = append(cands, ensemble.Candidate{Label: m.Label, Confidence: rules.Confidence(m), Layer: verdict.LayerRules})
		evRules[m.RecognizerID] = map[string]any{
			"matched": m.Matched, "total": m.Total, "checksum": m.HasChecksum,
		}
	}

	// Кластеризация до слоя 2 (п. 7.6): отпечаток по маскированным значениям;
	// член кластера с известным вердиктом представителя получает его копию.
	maskedVals := maskedForFingerprint(pool.Values)
	feat := fingerprint.Compute(col.NativeType, maskedVals, pool.Total, pool.Nulls)
	v.ClusterID = ""
	propagated := false
	if e.clusterer != nil {
		if id, ok := e.clusterer.Find(feat); ok {
			v.ClusterID = id
			if pv, ok := e.clusterer.Verdict(id); ok {
				applyClusterVerdict(&v, pv)
				propagated = true
				e.stats.propagated++
				observe.Default.IncrClusterPropagated() // п. 17
			} else {
				e.clusterer.Attach(id)
			}
		} else {
			v.ClusterID = e.clusterer.Register(feat)
		}
	}
	if propagated {
		e.finalizeVerdict(&v, pool, evRules)
		v.Evidence["cluster_propagated"] = true
		return v
	}

	// слой 2 (LLM) — только серый коридор и достаточный сэмпл (п. 7);
	// small_sample или null>0.95 → вызов не делается.
	gray := e.grayBand()
	weights := ensemble.Weights{}
	for k, wgt := range e.cfg.Weights {
		weights[verdict.EvidenceLayer(k)] = wgt
	}
	out := ensemble.Decide(cands, e.cfg.TauAccept, weights, gray)

	// серый коридор: вызов LLM-классификатора (этап 4) с кэшем вердиктов
	// (п. 10.5), затем эскалация в верификатор. Budget-стоп (п. 10.4): после
	// превышения cost_scan_limit_usd вызовы не делаются, колонка остаётся
	// pending с пометкой budget_exceeded.
	if e.llm != nil && out.Escalate && e.enoughForLLM(pool) {
		if e.budgetExceeded {
			if v.Evidence == nil {
				v.Evidence = map[string]any{}
			}
			v.Evidence["budget_exceeded"] = true
		} else {
			if res := e.llmClassify(ctx, col, pool, maskedVals, &v); res != nil {
				cands = append(cands, ensemble.Candidate{Label: verdict.Label(res.Label), Confidence: res.Confidence, Layer: verdict.LayerLLM})
				out = ensemble.Decide(cands, e.cfg.TauAccept, weights, gray)
			}
			// эскалация в верификатор, если решение всё ещё в серой зоне (п. 7 правило 4)
			if out.Escalate && !e.budgetExceeded {
				e.verifyGray(ctx, col, pool, &v, &out)
			}
		}
	}
	v.Label = out.Label
	v.Confidence = out.Confidence
	v.EvidenceLayer = out.Layer
	v.ReviewStatus = out.ReviewStatus
	e.finalizeVerdict(&v, pool, evRules)
	if v.ClusterID != "" && e.clusterer != nil {
		// вердикт представителя — источник для распространения (п. 7.6)
		e.clusterer.SetVerdict(v.ClusterID, cluster.VerdictView{
			Label: string(v.Label), Confidence: v.Confidence,
			Layer: string(v.EvidenceLayer), ReviewStatus: string(v.ReviewStatus),
		})
	}
	return v
}

// finalizeVerdict — общий хвост: sensitivity из таксономии, evidence,
// жёсткие правила small_sample (п. 6, п. 7). Evidence уже может содержать
// записи (llm_cache) — пополняется, не пересоздаётся.
func (e *Engine) finalizeVerdict(v *verdict.Verdict, pool *sampler.Pool, evRules map[string]any) {
	if s, ok := e.cfg.Sensitivity[v.Label]; ok {
		v.Sensitivity = s
	}
	if v.Evidence == nil {
		v.Evidence = map[string]any{}
	}
	v.Evidence["rules"] = evRules
	v.Evidence["sample"] = map[string]any{"values": len(pool.Values), "nulls": pool.Nulls, "total": pool.Total, "skipped": pool.Skipped}
	if len(pool.Values) == 0 || (pool.Total > 0 && float64(pool.Nulls)/float64(pool.Total) > 0.95) {
		v.Label = verdict.Label("UNKNOWN")
		v.ReviewStatus = verdict.StatusPending
		v.Evidence["reason"] = "small_sample"
	}
}

// applyClusterVerdict переносит вердикт представителя на члена кластера (п. 7.6).
func applyClusterVerdict(v *verdict.Verdict, pv cluster.VerdictView) {
	v.Label = verdict.Label(pv.Label)
	v.Confidence = pv.Confidence
	v.EvidenceLayer = verdict.EvidenceLayer(pv.Layer)
	v.ReviewStatus = verdict.ReviewStatus(pv.ReviewStatus)
}

// maskedForFingerprint маскирует значения пула для отпечатка (п. 7.6:
// префикс/суффикс — по маскированным значениям). Короткие (< MinLen) → "".
func maskedForFingerprint(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if m, ok := mask.Mask(v); ok {
			out = append(out, m)
		} else {
			out = append(out, "")
		}
	}
	return out
}

// cachedLLMVerdict — JSON-представление ответа классификатора в кэше (п. 10.5).
// Только лейбл/уверенность/версия промпта — без значений (ADR-0010).
type cachedLLMVerdict struct {
	Label         string  `json:"label"`
	Confidence    float64 `json:"confidence"`
	PromptVersion string  `json:"prompt_version"`
}

// llmClassify вызывает LLM-классификатора с кэшем вердиктов (п. 10.5): при
// промахе — вызов и запись в кэш (TTL CacheTTLDefault), при попадании —
// вердикт без сетевого обращения. Каждое обращение (вызов, ошибка, попадание
// в кэш) порождает запись agent_calls (п. 10.6), коммит — с вердиктами
// таблицы (п. 13). Возвращает nil при ошибке вызова.
func (e *Engine) llmClassify(ctx context.Context, col connector.Column, pool *sampler.Pool, maskedVals []string, v *verdict.Verdict) *agentproxy.ClassifyResult {
	cacheKey := ""
	if e.cfg.CacheScope != "" {
		cacheKey = llmCacheKey(e.cfg.CacheScope, e.cfg.TaxonomyVersion, fingerprint.ValuesHash(maskedVals))
		if cv, ok, err := e.st.CacheGet(ctx, cacheKey, e.nowFn()); err == nil && ok {
			if cached, err := decodeCachedVerdict(cv.VerdictJSON); err == nil {
				e.stats.cacheHits++
				setLLMCacheEvidence(v, cv.AgentID, true)
				// попадание в кэш — тоже учётная запись (cached=1, метрика
				// доли кэша п. 17); сетевого вызова и токенов нет
				e.recordCall(v, store.AgentCall{
					PromptVersion: cached.PromptVersion,
					Status:        "cache_hit",
					Cached:        true,
				})
				return cached
			}
		}
	}
	start := e.nowFn()
	res, err := e.llm.Classify(ctx, col.NativeType, pool.Values)
	measured := e.nowFn().Sub(start)
	if err != nil || res == nil {
		e.stats.llmErrors++
		e.recordCall(v, store.AgentCall{
			PromptVersion: prompts.Version, LatencyMS: int64(measured / time.Millisecond), Status: "error",
		})
		return nil
	}
	e.stats.llmCalls++
	v.PromptVersion = res.PromptVersion
	latency := res.Latency
	if latency <= 0 {
		latency = measured // fake-реализации latency не отдают — меряем сами
	}
	e.recordCall(v, store.AgentCall{
		PromptVersion: res.PromptVersion,
		TokensIn:      res.Usage.TokensIn, TokensOut: res.Usage.TokensOut,
		CostUSD:   e.callCost(ctx, res.Usage.TokensIn, res.Usage.TokensOut),
		LatencyMS: int64(latency / time.Millisecond),
		Status:    "ok",
	})
	if cacheKey != "" {
		if b, mErr := json.Marshal(cachedLLMVerdict{
			Label: res.Label, Confidence: res.Confidence, PromptVersion: res.PromptVersion,
		}); mErr == nil {
			now := e.nowFn()
			_ = e.st.CachePut(ctx, cacheKey, store.CachedVerdict{
				AgentID:     cacheAgentID(e.cfg.CacheScope),
				VerdictJSON: string(b),
				CreatedAt:   now,
				ExpiresAt:   now.Add(store.CacheTTLDefault),
			})
		}
		setLLMCacheEvidence(v, cacheAgentID(e.cfg.CacheScope), false)
	}
	return res
}

// verifyGray — эскалация в режим верификатора (п. 7 правило 4) с учётной
// записью вызова (п. 10.6): Verify основного агента или escalate_to — решает
// подставленный классификатор (в CLI — композит).
func (e *Engine) verifyGray(ctx context.Context, col connector.Column, pool *sampler.Pool, v *verdict.Verdict, out *ensemble.Outcome) {
	start := e.nowFn()
	vr, err := e.llm.Verify(ctx, string(out.GrayBest.Label), col.NativeType, pool.Values)
	measured := e.nowFn().Sub(start)
	if err != nil || vr == nil {
		e.stats.llmErrors++
		e.recordCall(v, store.AgentCall{
			PromptVersion: prompts.Version, LatencyMS: int64(measured / time.Millisecond), Status: "error",
		})
		return
	}
	latency := vr.Latency
	if latency <= 0 {
		latency = measured
	}
	e.recordCall(v, store.AgentCall{
		PromptVersion: prompts.Version,
		TokensIn:      vr.Usage.TokensIn, TokensOut: vr.Usage.TokensOut,
		CostUSD:   e.callCost(ctx, vr.Usage.TokensIn, vr.Usage.TokensOut),
		LatencyMS: int64(latency / time.Millisecond),
		Status:    "ok",
	})
	*out = ensemble.ApplyVerifier(*out, ensemble.VerifierOutcome{
		Verdict: vr.Verdict, Label: verdict.Label(vr.Label), Confidence: vr.Confidence,
	}, e.cfg.TauAccept)
}

// recordCall копит учётную запись вызова (п. 10.6) и парное аудит-событие
// (п. 14.2: каждый вызов агента — событие со ссылкой на agent_calls) в буфере
// таблицы; коммит — вместе с вердиктами (п. 13). Стоимость и токены
// накапливаются только по реальным ok-вызовам; при достижении
// cost_scan_limit_usd ставится budgetExceeded (п. 10.4).
func (e *Engine) recordCall(v *verdict.Verdict, call store.AgentCall) {
	call.ID = store.NewCallID()
	call.ScanID = v.ScanID
	call.VerdictID = v.ID
	if call.AgentID == "" {
		call.AgentID = e.llmID.AgentID
	}
	if call.Model == "" {
		call.Model = e.llmID.Model
	}
	call.CreatedAt = e.nowFn()
	e.calls = append(e.calls, call)
	e.events = append(e.events, audit.Event{
		Actor: e.actor(), Category: audit.CatAgent, Action: "agent_call",
		Target: "agent:" + call.AgentID, TS: call.CreatedAt,
		Details: map[string]any{
			"call_id": call.ID, "scan_id": call.ScanID, "verdict_id": call.VerdictID,
			"model": call.Model, "prompt_version": call.PromptVersion,
			"status": call.Status, "cached": call.Cached,
			"tokens_in": call.TokensIn, "tokens_out": call.TokensOut,
			"cost_usd": call.CostUSD, "latency_ms": call.LatencyMS,
		},
	})
	if call.Status == "ok" && !call.Cached {
		e.cost += call.CostUSD
		e.stats.tokensIn += call.TokensIn
		e.stats.tokensOut += call.TokensOut
		if e.cfg.CostScanLimitUSD > 0 && e.cost >= e.cfg.CostScanLimitUSD {
			e.budgetExceeded = true
		}
	}
	// процессные счётчики (п. 17, expvar /debug/vars)
	switch {
	case call.Cached:
		observe.Default.IncrCacheHit()
	case call.Status == "ok":
		observe.Default.IncrLLMCall()
		observe.Default.AddTokens(call.TokensIn, call.TokensOut)
		observe.Default.AddCostUSD(call.CostUSD)
	case call.Status == "error":
		observe.Default.IncrLLMError()
	}
}

// takeCalls возвращает буфер вызовов таблицы и очищает его (передача в
// транзакцию п. 13).
func (e *Engine) takeCalls() []store.AgentCall {
	calls := e.calls
	e.calls = nil
	return calls
}

// takeEvents — буфер аудит-событий таблицы (ADR-0013), коммит с вердиктами.
func (e *Engine) takeEvents() []audit.Event {
	events := e.events
	e.events = nil
	return events
}

// callCost — стоимость вызова по прайс-листу model_prices (п. 11.1):
// cost = tokens_in/1e6·per_1m_in + tokens_out/1e6·per_1m_out, округление
// до 6 знаков. Модели нет в прайсе → 0 (учёт без цены, п. 17).
func (e *Engine) callCost(ctx context.Context, tokensIn, tokensOut int) float64 {
	pin, pout, ok := e.priceFor(ctx, e.llmID.Model)
	if !ok {
		return 0
	}
	cost := float64(tokensIn)/1e6*pin + float64(tokensOut)/1e6*pout
	return math.Round(cost*1e6) / 1e6
}

// priceFor — цена модели с ленивым кэшем прайс-листа на скан.
func (e *Engine) priceFor(ctx context.Context, model string) (float64, float64, bool) {
	if e.prices == nil {
		e.prices = map[string]modelPrice{}
	}
	if p, ok := e.prices[model]; ok {
		return p.in, p.out, true
	}
	pin, pout, ok := e.st.PriceFor(ctx, model, e.nowFn())
	if !ok {
		return 0, 0, false
	}
	e.prices[model] = modelPrice{in: pin, out: pout}
	return pin, pout, true
}

func setLLMCacheEvidence(v *verdict.Verdict, agentID string, hit bool) {
	if v.Evidence == nil {
		v.Evidence = map[string]any{}
	}
	v.Evidence["llm_cache"] = map[string]any{"hit": hit, "agent_id": agentID}
}

func decodeCachedVerdict(s string) (*agentproxy.ClassifyResult, error) {
	var cv cachedLLMVerdict
	if err := json.Unmarshal([]byte(s), &cv); err != nil {
		return nil, err
	}
	return &agentproxy.ClassifyResult{
		Label: cv.Label, Confidence: cv.Confidence, PromptVersion: cv.PromptVersion,
	}, nil
}

// llmCacheKey — составной ключ кэша (blueprint п. 10.5):
// sha256(agent_id | model | prompt_version | taxonomy_version |
// mask_profile_version | fingerprint(values)).
func llmCacheKey(scope, taxonomyVersion, valuesHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"llm-classify", scope, prompts.Version, taxonomyVersion, mask.Version, valuesHash,
	}, "|")))
	return hex.EncodeToString(sum[:])
}

// cacheAgentID — часть CacheScope до '|' (agent_id для записи кэша).
func cacheAgentID(scope string) string {
	if i := strings.IndexByte(scope, '|'); i >= 0 {
		return scope[:i]
	}
	return scope
}

// grayBand — серая зона confidence для LLM/эскалации (confidence_band агента).
// По умолчанию [tau_review, tau_accept] если явно не задана.
func (e *Engine) grayBand() [2]float64 {
	if e.cfg.GrayBand[0] != 0 || e.cfg.GrayBand[1] != 0 {
		return e.cfg.GrayBand
	}
	lo := e.cfg.TauReview
	hi := e.cfg.TauAccept
	if lo <= 0 {
		lo = 0.3
	}
	if hi <= lo {
		hi = 0.7
	}
	return [2]float64{lo, hi}
}

// enoughForLLM — достаточно ли значений для вызова LLM (п. 7: сэмпл <
// min_values_for_llm или null>0.95 → вызов не делается).
func (e *Engine) enoughForLLM(pool *sampler.Pool) bool {
	min := e.cfg.MinValuesForLLM
	if min <= 0 {
		min = 3
	}
	if len(pool.Values) < min {
		return false
	}
	if pool.Total > 0 && float64(pool.Nulls)/float64(pool.Total) > 0.95 {
		return false
	}
	return true
}

// newScanID — уникальный id прогона (время + случайность).
func newScanID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%d-%s", now.Unix(), hex.EncodeToString(b[:]))
}
