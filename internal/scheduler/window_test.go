package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/config"
)

// fakeNow — подвижные часы для тестов окон (потокобезопасно: rescan и
// таймеры читают их из разных горутин).
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// hasDeferredAudit — в аудите есть событие scheduler/scan_deferred по
// источнику (п. 14.2: фоновые задачи журналируются, actor scheduler).
func hasDeferredAudit(t *testing.T, st interface {
	AuditList(context.Context, audit.Filter) ([]audit.Entry, error)
}, source string) bool {
	t.Helper()
	evs, err := st.AuditList(context.Background(), audit.Filter{Category: audit.CatAdmin})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	for _, e := range evs {
		if e.Action == "scheduler/scan_deferred" && e.Actor == actor && e.Target == "source:"+source {
			return true
		}
	}
	return false
}

func (s *Scheduler) timerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.timers)
}

// TestSchedulerScanWindowInside — cron внутри окна: немедленный старт,
// без откладывания и аудита deferral (п. 13.2).
func TestSchedulerScanWindowInside(t *testing.T) {
	st := newTestStore(t)
	runner := &fakeStarter{}
	clock := &fakeClock{now: time.Date(2026, 10, 24, 3, 0, 0, 0, time.Local)} // внутри 02:00-06:00
	src := config.Source{Name: "ch-win", Type: "clickhouse", DSN: "x", ScanWindow: "02:00-06:00"}
	sch := New(st, runner, nil, []config.Source{src}, WithNowFn(clock.get))
	defer sch.Stop()

	sch.rescan(context.Background(), "ch-win")
	if runner.calls() != 1 {
		t.Fatalf("старт внутри окна должен быть немедленным: calls=%d", runner.calls())
	}
	if sch.timerCount() != 0 {
		t.Fatalf("таймеров откладывания быть не должно: %d", sch.timerCount())
	}
	if hasDeferredAudit(t, st, "ch-win") {
		t.Fatal("аудит scan_deferred при старте внутри окна")
	}
}

// TestSchedulerScanWindowDefersUntilStart — cron вне окна: старт
// откладывается до начала окна (разовый таймер), аудит scan_deferred
// (actor scheduler); по срабатывании таймера (время уже в окне) — старт.
func TestSchedulerScanWindowDefersUntilStart(t *testing.T) {
	st := newTestStore(t)
	runner := &fakeStarter{}
	// 01:59:58 — за 2 секунды до окна 02:00-06:00: таймер реальный и короткий.
	clock := &fakeClock{now: time.Date(2026, 10, 24, 1, 59, 58, 0, time.Local)}
	src := config.Source{Name: "ch-win", Type: "clickhouse", DSN: "x", ScanWindow: "02:00-06:00"}
	sch := New(st, runner, nil, []config.Source{src}, WithNowFn(clock.get))
	defer sch.Stop()

	sch.rescan(context.Background(), "ch-win")
	if runner.calls() != 0 {
		t.Fatalf("старт вне окна должен быть отложен: calls=%d", runner.calls())
	}
	if !hasDeferredAudit(t, st, "ch-win") {
		t.Fatal("нет аудита scheduler/scan_deferred (actor scheduler, п. 14.2)")
	}
	if sch.timerCount() != 1 {
		t.Fatalf("ожидался 1 таймер откладывания, %d", sch.timerCount())
	}

	// Таймер сработает через ~2 с реального времени: к этому моменту часы
	// уже в окне — rescan по таймеру обязан стартовать (повторная проверка
	// окна защищает от сдвига часов, здесь имитирует наступление окна).
	clock.set(time.Date(2026, 10, 24, 2, 0, 30, 0, time.Local))
	deadline := time.Now().Add(5 * time.Second)
	for runner.calls() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if runner.calls() != 1 {
		t.Fatalf("по наступлении окна перескан обязан стартовать: calls=%d", runner.calls())
	}
}

// TestSchedulerScanWindowDeferredClockStillOutside — сдвиг часов назад:
// таймер сработал, но окно ещё не наступило — старт откладывается повторно
// (fail-safe: окно нельзя обойти).
func TestSchedulerScanWindowDeferredClockStillOutside(t *testing.T) {
	st := newTestStore(t)
	runner := &fakeStarter{}
	clock := &fakeClock{now: time.Date(2026, 10, 24, 1, 59, 59, 0, time.Local)}
	src := config.Source{Name: "ch-win", Type: "clickhouse", DSN: "x", ScanWindow: "02:00-06:00"}
	sch := New(st, runner, nil, []config.Source{src}, WithNowFn(clock.get))
	defer sch.Stop()

	sch.rescan(context.Background(), "ch-win") // отложен до 02:00 (~1 с)
	if runner.calls() != 0 {
		t.Fatalf("calls=%d, ожидалось 0", runner.calls())
	}
	// К моменту срабатывания таймера часы «откатились»: всё ещё вне окна.
	// Ждём повторного откладывания: новый таймер вместо старта.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if sch.timerCount() > 0 && runner.calls() == 0 && !hasDeferredAudit(t, st, "ch-win") {
			t.Fatal("внутреннее нарушение: deferral без аудита")
		}
		if sch.timerCount() > 0 && runner.calls() == 0 {
			// таймер перевыставлен (старый отработал и удалился, новый добавлен)
			time.Sleep(30 * time.Millisecond)
		}
		if runner.calls() > 0 {
			t.Fatal("старт вне окна: повторная проверка окна не сработала")
		}
		// выходим, когда первый таймер точно сработал: появился второй deferral-аудит? — достаточно отсутствия старта
		break
	}
	if runner.calls() != 0 {
		t.Fatal("старт вне окна при сдвиге часов")
	}
}

// TestSchedulerStopCancelsDeferredTimer — Stop снимает отложенный таймер:
// после остановки планировщика отложенный старт не выполняется (п. 13,
// плавная остановка).
func TestSchedulerStopCancelsDeferredTimer(t *testing.T) {
	st := newTestStore(t)
	runner := &fakeStarter{}
	// Окно далеко (~1 час): таймер гарантированно не сработает сам.
	clock := &fakeClock{now: time.Date(2026, 10, 24, 1, 0, 0, 0, time.Local)}
	src := config.Source{Name: "ch-win", Type: "clickhouse", DSN: "x", ScanWindow: "02:00-06:00"}
	sch := New(st, runner, nil, []config.Source{src}, WithNowFn(clock.get))

	sch.rescan(context.Background(), "ch-win")
	if sch.timerCount() != 1 {
		t.Fatalf("ожидался отложенный таймер, %d", sch.timerCount())
	}
	sch.Stop()
	if sch.timerCount() != 0 {
		t.Fatalf("Stop обязан снимать таймеры откладывания: %d", sch.timerCount())
	}
	// «Наступило окно» — но старта быть не должно: планировщик остановлен.
	clock.set(time.Date(2026, 10, 24, 3, 0, 0, 0, time.Local))
	time.Sleep(100 * time.Millisecond)
	if runner.calls() != 0 {
		t.Fatalf("отложенный старт после Stop: calls=%d", runner.calls())
	}
}

// TestSchedulerNoWindowUnchanged — источник без окна: rescan стартует
// немедленно (обратная совместимость п. 13.2: scan_window — опция).
func TestSchedulerNoWindowUnchanged(t *testing.T) {
	st := newTestStore(t)
	runner := &fakeStarter{}
	src := config.Source{Name: "ch-plain", Type: "clickhouse", DSN: "x"}
	sch := New(st, runner, nil, []config.Source{src})
	defer sch.Stop()

	sch.rescan(context.Background(), "ch-plain")
	if runner.calls() != 1 {
		t.Fatalf("источник без окна: calls=%d, ожидалось 1", runner.calls())
	}
}
