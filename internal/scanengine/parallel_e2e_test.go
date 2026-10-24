package scanengine

import (
	"context"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/connector"
)

// parConnector — потокобезопасный fake-источник для тестов параллельного
// пути (S8-2, п. 13.2): fakeConnector из engine_test не сynchronised и годится
// только для последовательных прогонов.
type parConnector struct {
	mu      sync.Mutex
	tables  []connector.TableRef
	delay   time.Duration // искусственная задержка GetSchema (замер параллелизма)
	err     error         // задана — GetSchema всегда отдаёт её (имитация сбоя)
	cur     int           // текущее число активных GetSchema
	maxSeen int           // максимум одновременных GetSchema

	// waitCtx: GetSchema блокируется до отмены ctx (тест мягкой остановки и
	// дедлайна запроса). hasDeadline — последний наблюдаемый признак дедлайна.
	waitCtx     bool
	hasDeadline atomic.Bool

	closed chan struct{} // закрывается в Close (ожидание завершения в тестах)
}

func newParConnector(n int) *parConnector {
	c := &parConnector{closed: make(chan struct{})}
	for i := 1; i <= n; i++ {
		c.tables = append(c.tables, connector.TableRef{Schema: "public", Name: fmt.Sprintf("t%02d", i)})
	}
	return c
}

func (c *parConnector) Ping(ctx context.Context) error { return nil }

func (c *parConnector) ListTables(ctx context.Context) ([]connector.TableRef, error) {
	return c.tables, nil
}

func (c *parConnector) GetSchema(ctx context.Context, t connector.TableRef) ([]connector.Column, error) {
	_, has := ctx.Deadline()
	c.hasDeadline.Store(has)
	c.mu.Lock()
	c.cur++
	if c.cur > c.maxSeen {
		c.maxSeen = c.cur
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.cur--; c.mu.Unlock() }()

	if c.err != nil {
		return nil, c.err
	}
	if c.waitCtx {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []connector.Column{{Name: "v", NativeType: "String"}}, nil
}

func (c *parConnector) CountRows(ctx context.Context, t connector.TableRef) (int64, error) {
	return 1, nil
}

func (c *parConnector) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	return func(yield func(connector.Row, error) bool) {
		// 5 различных значений: достаточно для LLM-слоя (min_values_for_llm,
		// п. 7) при dedup
		for _, v := range []string{"x1", "x2", "x3", "x4", "x5"} {
			if !yield(connector.Row{spec.Columns[0]: v}, nil) {
				return
			}
		}
	}, nil
}

func (c *parConnector) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *parConnector) maxConcurrent() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxSeen
}

// TestParallelRespectsMaxTables — gate не пускает больше MaxTables
// одновременных таблиц (п. 13.2, max_concurrent_tables).
func TestParallelRespectsMaxTables(t *testing.T) {
	eng, _ := testEngine(t)
	eng.cfg.MaxTables = 2

	conn := newParConnector(6)
	conn.delay = 50 * time.Millisecond
	rep, err := eng.Scan(context.Background(), conn, "par", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Status != "done" || rep.TablesDone != 6 || rep.TablesFailed != 0 {
		t.Fatalf("результат: status=%s done=%d failed=%d, ожидалось done/6/0",
			rep.Status, rep.TablesDone, rep.TablesFailed)
	}
	if got := conn.maxConcurrent(); got > 2 {
		t.Fatalf("одновременных GetSchema: %d, лимит MaxTables=2", got)
	}
}

// TestParallelBreakerMatchesSequential — серия breaker'а в параллельном
// пути детерминирована порядком ListTables (ADR-impl S8-2 D3): те же
// счётчики и флаг, что у последовательного прогона (S8-1). Overload
// имитируется дедлайном на GetSchema каждой таблицы (потокобезопасный
// parConnector; fakeConnector/overloadTables — только для sequential).
func TestParallelBreakerMatchesSequential(t *testing.T) {
	eng, st := testEngine(t)
	eng.cfg.Breaker = NewBreaker()
	eng.cfg.MaxTables = 2

	conn := newParConnector(6)
	conn.err = context.DeadlineExceeded
	rep, err := eng.Scan(context.Background(), conn, "ch-test", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Status != "partial" || rep.TablesFailed != breakerConsecutiveFails || !rep.BreakerTripped {
		t.Fatalf("результат: status=%s failed=%d tripped=%v, ожидалось partial/%d/true",
			rep.Status, rep.TablesFailed, rep.BreakerTripped, breakerConsecutiveFails)
	}
	if rep.TablesDone != 0 {
		t.Fatalf("TablesDone: %d, ожидалось 0", rep.TablesDone)
	}
	entries, err := st.AuditList(context.Background(), audit.Filter{Category: audit.CatScan})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	paused := false
	for _, e := range entries {
		if e.Action == "source_paused" {
			paused = true
		}
	}
	if !paused {
		t.Fatal("нет аудит-события source_paused (п. 14.2)")
	}
}

// TestParallelInterruptedNoFalseFailures — мягкая остановка (ctx) в
// параллельном пути: статус interrupted, in-flight таблицы не считаются
// failed и не кормят серию breaker'а (п. 11.2, п. 13.2).
func TestParallelInterruptedNoFalseFailures(t *testing.T) {
	eng, _ := testEngine(t)
	eng.cfg.Breaker = NewBreaker()
	eng.cfg.MaxTables = 2

	ctx, cancel := context.WithCancel(context.Background())
	conn := newParConnector(4)
	conn.waitCtx = true // GetSchema блокируется до отмены

	done := make(chan *Report, 1)
	go func() {
		rep, err := eng.Scan(ctx, conn, "par-stop", "quick")
		if err != nil {
			t.Errorf("Scan: %v", err)
		}
		done <- rep
	}()
	time.Sleep(100 * time.Millisecond) // прогон дошёл до заблокированных таблиц
	cancel()
	rep := <-done
	if rep == nil {
		t.Fatal("Scan вернул nil отчёт при отмене")
	}

	if rep.Status != "interrupted" {
		t.Fatalf("статус: %s, ожидался interrupted", rep.Status)
	}
	if rep.TablesFailed != 0 || rep.BreakerTripped {
		t.Fatalf("отмена не должна давать failed/breaker: failed=%d tripped=%v",
			rep.TablesFailed, rep.BreakerTripped)
	}
}

// TestParallelQueryTimeout — query_timeout источника: каждый запрос к БД
// получает дедлайн; дедлайн классифицируется overload (S8-1), retryable —
// итог по таблицам failed, но серия из двух не трипает breaker (порог 5).
func TestParallelQueryTimeout(t *testing.T) {
	eng, _ := testEngine(t)
	eng.cfg.Breaker = NewBreaker()
	eng.cfg.MaxTables = 2
	eng.cfg.QueryTimeout = 20 * time.Millisecond

	conn := newParConnector(2)
	conn.waitCtx = true // без внешней отмены выход только по дедлайну запроса
	rep, err := eng.Scan(context.Background(), conn, "par-timeout", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !conn.hasDeadline.Load() {
		t.Fatal("запрос к БД без дедлайна при заданном QueryTimeout (п. 13.2)")
	}
	if rep.Status != "partial" || rep.TablesFailed != 2 {
		t.Fatalf("результат: status=%s failed=%d, ожидалось partial/2", rep.Status, rep.TablesFailed)
	}
	if rep.BreakerTripped {
		t.Fatal("серия из двух overload не должна трипать breaker (порог 5)")
	}
}

// TestParallelLLMRace — LLM-слой и кластеризация под параллельными
// воркерами: запуск под -race, итоговые счётчики согласованы с вердиктами.
func TestParallelLLMRace(t *testing.T) {
	eng, st := testEngine(t)
	eng.cfg.MaxTables = 3
	eng.cfg.Clustering = true // кластеризация под воркерами (п. 7.6, race)
	eng.SetLLM(llmWithAnswer(), LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})

	conn := newParConnector(4)
	rep, err := eng.Scan(context.Background(), conn, "par-llm", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Status != "done" || rep.TablesDone != 4 {
		t.Fatalf("результат: status=%s done=%d, ожидалось done/4", rep.Status, rep.TablesDone)
	}
	if rep.Verdicts != 4 { // 1 колонка × 4 таблицы
		t.Fatalf("вердиктов: %d, ожидалось 4", rep.Verdicts)
	}
	vs, err := st.ListVerdicts(context.Background(), rep.ScanID)
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	if len(vs) != rep.Verdicts {
		t.Fatalf("вердиктов в store: %d, в отчёте: %d", len(vs), rep.Verdicts)
	}
	if rep.LLMCalls+rep.CacheHits+rep.ClusterPropagated == 0 {
		t.Fatal("LLM/кэш/кластер не сработали ни разу — счётчики потеряны под параллелизмом?")
	}
}
