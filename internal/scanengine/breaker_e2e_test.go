package scanengine

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// overloadTables — источник из n таблиц, GetSchema каждой падает дедлайном
// (retryable → причина source_overload по классификации п. 13.2).
func overloadTables(n int) *fakeConnector {
	f := &fakeConnector{
		tables:   map[string][]connector.Column{},
		data:     map[string][]connector.Row{},
		errs:     map[string]error{},
		errCount: map[string]int{},
		calls:    map[string]int{},
	}
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("t%02d", i)
		f.tables[name] = []connector.Column{{Name: "v", NativeType: "String"}}
		f.data[name] = []connector.Row{{"v": "x"}}
		f.errs["schema:"+name] = context.DeadlineExceeded
	}
	return f
}

func TestBreakerTripPauseAndRefuse(t *testing.T) {
	eng, st := testEngine(t)
	ctx := context.Background()
	br := NewBreaker()
	eng.cfg.Breaker = br

	// 6 таблиц: breaker должен остановить прогон после 5-й (п. 13.2).
	rep, err := eng.Scan(ctx, overloadTables(6), "ch-test", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Status != "partial" {
		t.Fatalf("статус: %s, ожидался partial", rep.Status)
	}
	if rep.TablesFailed != breakerConsecutiveFails {
		t.Fatalf("TablesFailed: %d, ожидалось %d", rep.TablesFailed, breakerConsecutiveFails)
	}
	if !rep.BreakerTripped {
		t.Fatal("BreakerTripped=false после серии overload-ошибок")
	}
	if rep.TablesTotal != 6 || rep.TablesDone != 0 {
		t.Fatalf("таблицы: total=%d done=%d", rep.TablesTotal, rep.TablesDone)
	}

	// 6-я таблица не тронута: чекпоинта нет (resume догонит).
	entries, err := st.AuditList(ctx, audit.Filter{Category: audit.CatScan})
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

	// Повторный прогон в паузе — отказ до старта (строка scans не появилась).
	if _, err := eng.Scan(ctx, overloadTables(1), "ch-test", "quick"); err == nil {
		t.Fatal("второй прогон в паузе: ожидался отказ")
	} else {
		p, ok := ErrSourcePaused(err)
		if !ok {
			t.Fatalf("отказ не SourcePausedError: %v", err)
		}
		if p.Until.Before(eng.nowFn()) {
			t.Fatalf("пауза уже истекла: %v", p.Until)
		}
	}
	_, total, err := st.ListScans(ctx, store.ScanFilter{})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if total != 1 {
		t.Fatalf("scans: %d, ожидался 1 (отказанный прогон не создаётся)", total)
	}

	// После истечения паузы прогон снова возможен: сдвигаем часы движка
	// (re-trip паузу не сокращает — Trip идемпотентен в пределах паузы).
	baseNow := eng.nowFn
	eng.nowFn = func() time.Time { return baseNow().Add(breakerPause + time.Minute) }
	if err := br.PausedErr("ch-test", eng.nowFn()); err != nil {
		t.Fatalf("после истечения паузы: %v", err)
	}
}

func TestStreakResetByOtherFailure(t *testing.T) {
	eng, _ := testEngine(t)
	eng.cfg.Breaker = NewBreaker()

	// 4 overload → 1 прочая ошибка (обрывает серию) → ещё 4 overload:
	// breaker не срабатывает (9 таблиц обработаны, все failed).
	f := overloadTables(9)
	other := errors.New("permission denied")
	f.errs["schema:t05"] = other
	delete(f.errCount, "schema:t05")
	rep, err := eng.Scan(context.Background(), f, "ch-test", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.BreakerTripped {
		t.Fatal("breaker сработал, хотя серию оборвала не-overload ошибка")
	}
	if rep.TablesFailed != 9 {
		t.Fatalf("TablesFailed: %d, ожидалось 9", rep.TablesFailed)
	}
}

func TestRetryOnRetryableThenSuccess(t *testing.T) {
	eng, _ := testEngine(t)
	eng.cfg.Breaker = NewBreaker()

	// Таблица падает дедлайном 2 раза, на 3-й попытке отдаётся.
	f := overloadTables(1)
	f.errCount["schema:t01"] = 2
	rep, err := eng.Scan(context.Background(), f, "ch-test", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Status != "done" || rep.TablesDone != 1 || rep.TablesFailed != 0 {
		t.Fatalf("результат: status=%s done=%d failed=%d, ожидалось done/1/0",
			rep.Status, rep.TablesDone, rep.TablesFailed)
	}
	if got := f.calls["schema:t01"]; got != 3 {
		t.Fatalf("попыток GetSchema: %d, ожидалось 3", got)
	}

	// Не-retryable ошибка не повторяется: одна попытка.
	f2 := overloadTables(1)
	f2.errs["schema:t01"] = errors.New("permission denied")
	rep2, err := eng.Scan(context.Background(), f2, "ch-test", "quick")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep2.TablesFailed != 1 || f2.calls["schema:t01"] != 1 {
		t.Fatalf("не-retryable: failed=%d calls=%d, ожидалось 1/1",
			rep2.TablesFailed, f2.calls["schema:t01"])
	}
}

func TestResumeSkipsDoneTables(t *testing.T) {
	eng, _ := testEngine(t)
	ctx := context.Background()

	// Прогон 1: t01 healthy, t02 падает навсегда → partial.
	f := overloadTables(2)
	f.errs["schema:t01"] = nil
	f.errs["schema:t02"] = errors.New("constraint violation")
	rep1, err := eng.Scan(ctx, f, "ch-test", "quick")
	if err != nil {
		t.Fatalf("прогон 1: %v", err)
	}
	if rep1.Status != "partial" {
		t.Fatalf("прогон 1: статус %s, ожидался partial", rep1.Status)
	}

	// Прогон 2 с resume: t01 пропущена, t02 вылечилась и обработалась.
	f2 := overloadTables(2)
	f2.errs["schema:t01"] = nil
	f2.errs["schema:t02"] = nil
	eng.cfg.ResumeFrom = rep1.ScanID
	rep2, err := eng.Scan(ctx, f2, "ch-test", "quick")
	if err != nil {
		t.Fatalf("прогон 2: %v", err)
	}
	if rep2.ResumeFrom != rep1.ScanID || rep2.Skipped != 1 {
		t.Fatalf("resume: from=%q skipped=%d, ожидалось %s/1", rep2.ResumeFrom, rep2.Skipped, rep1.ScanID)
	}
	if rep2.TablesTotal != 2 || rep2.TablesDone != 1 || rep2.Status != "done" {
		t.Fatalf("прогон 2: total=%d done=%d status=%s, ожидалось 2/1/done",
			rep2.TablesTotal, rep2.TablesDone, rep2.Status)
	}
	if got := f2.calls["schema:t01"]; got != 0 {
		t.Fatalf("t01 перечитана при resume: %d вызовов, ожидалось 0", got)
	}
}
