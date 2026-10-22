// Тесты встроенного планировщика (blueprint п. 15, п. 15.4): задачи на cron
// с ускоренным расписанием (@every 1s) — прочистка кэша, retention,
// периодические пересканы, невалидное расписание источника.
package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// fakeStarter — тестовый ScanStarter: считает запуски.
type fakeStarter struct {
	mu     sync.Mutex
	actors []string
}

func (f *fakeStarter) Start(source, _, actor string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, source+"|"+actor)
	return "scan-" + source, nil
}

func (f *fakeStarter) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.actors)
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/sched.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// waitFor опрашивает cond до успеха или дедлайна — стабильнее фиксированного
// sleep на медленных машинах/под race-detector'ом.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("таймаут ожидания: %s", what)
}

func auditActions(t *testing.T, st *store.Store, action string) []audit.Entry {
	t.Helper()
	entries, err := st.AuditList(context.Background(), audit.Filter{})
	if err != nil {
		t.Fatalf("AuditList: %v", err)
	}
	var out []audit.Entry
	for _, e := range entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// Прочистка verdict_cache: просроченная запись удалена, факт — в аудит.
func TestSchedulerCachePurge(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.CachePut(ctx, "key-expired", store.CachedVerdict{
		AgentID: "a", VerdictJSON: `{"label":"EMAIL"}`,
		CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CachePut: %v", err)
	}
	if err := st.CachePut(ctx, "key-fresh", store.CachedVerdict{
		AgentID: "a", VerdictJSON: `{"label":"EMAIL"}`,
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("CachePut: %v", err)
	}

	sch := New(st, nil, nil, nil, WithSpecs("@every 1s", "@yearly"))
	if err := sch.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sch.Stop()

	waitFor(t, 5*time.Second, "аудит scheduler/cache_purge", func() bool {
		return len(auditActions(t, st, "scheduler/cache_purge")) > 0
	})
	_, ok, err := st.CacheGet(ctx, "key-expired", now)
	if err != nil || ok {
		t.Fatal("просроченная запись кэша не удалена")
	}
	if _, ok, err := st.CacheGet(ctx, "key-fresh", now); err != nil || !ok {
		t.Fatal("свежая запись кэша удалена")
	}
	events := auditActions(t, st, "scheduler/cache_purge")
	if len(events) == 0 {
		t.Fatal("нет аудит-события scheduler/cache_purge")
	}
	if events[0].Actor != "scheduler" || events[0].Category != audit.CatAdmin {
		t.Fatalf("actor/category: %+v", events[0])
	}
	if removed, _ := events[0].Details["removed"].(float64); removed != 1 {
		t.Fatalf("details.removed=%v, ожидался 1", events[0].Details["removed"])
	}
}

// Retention: старый прогон со связанными удалён, свежий остался, факт — в аудит.
func TestSchedulerRetention(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	oldFinished := now.Add(-91 * 24 * time.Hour)
	if err := st.SaveScan(ctx, &store.Scan{ID: "old", SourceName: "ch", Profile: "quick",
		Status: "running", StartedAt: oldFinished.Add(-time.Hour)}); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if err := st.FinishScan(ctx, "old", "done", "{}", oldFinished); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}
	freshFinished := now.Add(-time.Hour)
	if err := st.SaveScan(ctx, &store.Scan{ID: "fresh", SourceName: "ch", Profile: "quick",
		Status: "running", StartedAt: freshFinished.Add(-time.Hour)}); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	if err := st.FinishScan(ctx, "fresh", "done", "{}", freshFinished); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}

	sch := New(st, nil, nil, nil, WithSpecs("@yearly", "@every 1s"))
	if err := sch.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sch.Stop()

	waitFor(t, 5*time.Second, "аудит scheduler/retention_purge", func() bool {
		return len(auditActions(t, st, "scheduler/retention_purge")) > 0
	})
	if _, err := st.GetScan(ctx, "old"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("старый прогон не удалён: %v", err)
	}
	if _, err := st.GetScan(ctx, "fresh"); err != nil {
		t.Fatalf("свежий прогон удалён: %v", err)
	}
	events := auditActions(t, st, "scheduler/retention_purge")
	if len(events) == 0 {
		t.Fatal("нет аудит-события scheduler/retention_purge")
	}
	if v, _ := events[len(events)-1].Details["removed_scans"].(float64); v != 1 {
		t.Fatalf("removed_scans=%v, ожидался 1", events[len(events)-1].Details["removed_scans"])
	}
}

// Периодический перескан: источник с @every 1s запускает runner от
// actor "scheduler"; невалидное расписание не роняет Start и аудируется.
func TestSchedulerRescanAndInvalidSchedule(t *testing.T) {
	st := newTestStore(t)
	runner := &fakeStarter{}
	sources := []config.Source{
		{Name: "ch-ok", Type: "clickhouse", DSN: "clickhouse://x", Schedule: "@every 1s"},
		{Name: "ch-bad", Type: "clickhouse", DSN: "clickhouse://y", Schedule: "not a cron spec"},
	}
	sch := New(st, runner, nil, sources, WithSpecs("@yearly", "@yearly"))
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start с невалидным расписанием источника не должен падать: %v", err)
	}
	defer sch.Stop()

	waitFor(t, 5*time.Second, "периодический перескан", func() bool { return runner.calls() >= 1 })
	if got := auditActions(t, st, "scheduler/invalid_schedule"); len(got) != 1 {
		t.Fatalf("аудит invalid_schedule: %d событий", len(got))
	}
}

// Повторный Start — ошибка; Stop без Start — no-op.
func TestSchedulerLifecycle(t *testing.T) {
	st := newTestStore(t)
	sch := New(st, nil, nil, nil)
	sch.Stop() // без Start — не паникует
	if err := sch.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sch.Stop()
	if err := sch.Start(context.Background()); err == nil {
		t.Fatal("повторный Start должен вернуть ошибку")
	}
}

// TestSchedulerAlerts — задача оценки алертов (S6в, п. 17): fn вызывается
// по расписанию; паника fn не роняет cron-цикл (recover).
func TestSchedulerAlerts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	var calls atomic.Int64
	done := make(chan struct{})
	sch := New(st, nil, nil, nil,
		WithSpecs("@yearly", "@yearly"),
		WithAlerts("@every 1s", func(ctx context.Context) {
			if calls.Add(1) >= 2 {
				select {
				case done <- struct{}{}:
				default:
				}
			}
		}))
	if err := sch.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sch.Stop()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("alerts fn не вызвана (calls=%d)", calls.Load())
	}
}
