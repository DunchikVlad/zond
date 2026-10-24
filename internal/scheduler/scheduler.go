// Package scheduler — встроенный планировщик процесса serve (blueprint п. 15,
// п. 15.4, ADR-0014): фоновые задачи инстанса — прочистка verdict_cache,
// retention сканов и периодические пересканы источников по расписанию из
// connections.yaml (поле source.schedule).
//
// Задачи (все события — в аудит-лог, actor "scheduler", п. 14.2
// «фоновые задачи журналируются»):
//
//  1. прочистка verdict_cache — ежедневно в 03:17 локального времени
//     (st.CachePurgeExpired → аудит scheduler/cache_purge {removed});
//
//  2. retention сканов — ежедневно в 04:23: удаление прогонов старше 90 дней
//     вместе со связанными данными (st.PurgeScansOlderThan → аудит
//     scheduler/retention_purge {removed_scans, cutoff});
//
//  3. периодические пересканы: для каждого источника cfg с непустым schedule
//     (cron-выражение) — runner.Start(source, "", "scheduler"). Невалидное
//     выражение → warn-лог + аудит scheduler/invalid_schedule {source,
//     schedule}, источник пропускается (старт не падает);
//
//  4. оценка алертов (S6в, п. 17) — alertsFn по расписанию specAlerts
//     (default каждые 5 минут; подключается WithAlerts; nil — выключено);
//
//  5. резервное копирование (S7б, п. 15.2) — online-копия БД в backupDir по
//     расписанию backupSpec (подключается WithBackup; пусто — выключено).
//     Факт каждой попытки (ok/fail) — в аудит, читает правило backup_failed.
//
//  6. окна сканирования (S8-2, п. 13.2): источник с scan_window
//     ("HH:MM-HH:MM", локальное время) — срабатывание cron вне окна
//     откладывает старт до начала окна (разовый таймер; аудит
//     scheduler/scan_deferred); ручные запуски (API/CLI) окном не
//     ограничиваются — это осознанное действие оператора.
package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// actor — автор аудит-событий фоновых задач (п. 14.2).
const actor = "scheduler"

// Стандартные расписания фоновых задач (локальное время инстанса).
const (
	specCachePurge = "17 3 * * *"  // ежедневно 03:17
	specRetention  = "23 4 * * *"  // ежедневно 04:23
	specAlerts     = "*/5 * * * *" // алертинг каждые 5 минут (п. 17)
)

// retentionAge — срок хранения сканов + вердиктов + agent_calls
// (blueprint п. 15.4: ≥90 дней; автоочистка шедулером).
const retentionAge = 90 * 24 * time.Hour

// ScanStarter — тот же интерфейс, что api.ScanRunner/web.ScanRunner: запуск
// асинхронного прогона (п. 11.2); реализация — runner поверх scanengine.
type ScanStarter interface {
	Start(source, profile, actor string) (string, error)
}

// Scheduler — cron-планировщик фоновых задач инстанса (single-instance,
// ADR-0014: один процесс serve = один шедулер).
type Scheduler struct {
	st      *store.Store
	runner  ScanStarter
	log     *slog.Logger
	sources []config.Source
	cron    *cron.Cron
	nowFn   func() time.Time
	windows map[string]config.Window // scan_window источников (п. 13.2)

	// Отложенные старты (окно сканирования, п. 13.2): разовые таймеры до
	// начала окна; Stop останавливает вместе с cron.
	mu     sync.Mutex
	timers map[*time.Timer]struct{}

	purgeSpec     string
	retentionSpec string
	retentionAge  time.Duration

	// Инкремент S6в: оценка алертов (п. 17); nil — задача не регистрируется.
	alertsSpec string
	alertsFn   func(ctx context.Context)

	// Инкремент S7б: периодическая копия БД (п. 15.2); пустой spec — выключено.
	backupSpec string
	backupDir  string
}

// Option — настройка планировщика (в тестах — ускоренные расписания).
type Option func(*Scheduler)

// WithSpecs задаёт cron-выражения задач прочистки кэша и retention.
func WithSpecs(cachePurge, retention string) Option {
	return func(s *Scheduler) {
		if cachePurge != "" {
			s.purgeSpec = cachePurge
		}
		if retention != "" {
			s.retentionSpec = retention
		}
	}
}

// WithRetentionAge задаёт срок хранения сканов (п. 15.4: default 90 дней).
func WithRetentionAge(d time.Duration) Option {
	return func(s *Scheduler) {
		if d > 0 {
			s.retentionAge = d
		}
	}
}

// WithAlerts подключает периодическую оценку алертов (S6в, blueprint п. 17):
// fn запускается по cron-расписанию spec (пусто → "*/5 * * * *"). События
// алертов пишет сама fn (аудит категории alert, actor scheduler).
func WithAlerts(spec string, fn func(ctx context.Context)) Option {
	return func(s *Scheduler) {
		if spec != "" {
			s.alertsSpec = spec
		}
		s.alertsFn = fn
	}
}

// WithBackup подключает периодическую онлайн-копию БД (S7б, п. 15.2):
// VACUUM INTO в backupDir по cron-расписанию spec (конфиг connections.yaml
// backup.{schedule,dir}). Попытка (ok/fail с ошибкой) — в аудит backup.
// Регистрация задачи — только при непустом spec (Start).
func WithBackup(spec, dir string) Option {
	return func(s *Scheduler) {
		s.backupSpec = spec
		s.backupDir = dir
	}
}

// WithNowFn подменяет часы (тесты).
func WithNowFn(fn func() time.Time) Option {
	return func(s *Scheduler) { s.nowFn = fn }
}

// New собирает планировщик; log nil → discard. Регистрация задач — Start.
// Окна сканирования (scan_window) разбираются здесь: формат гарантирован
// валидацией конфига (fail-fast, п. 13.2); битое значение (прямая сборка в
// тестах) — источник без окна.
func New(st *store.Store, runner ScanStarter, log *slog.Logger, sources []config.Source, opts ...Option) *Scheduler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	windows := map[string]config.Window{}
	for _, src := range sources {
		if src.ScanWindow == "" {
			continue
		}
		if w, err := config.ParseWindow(src.ScanWindow); err == nil {
			windows[src.Name] = w
		}
	}
	s := &Scheduler{
		st: st, runner: runner, log: log, sources: sources,
		nowFn:         time.Now,
		windows:       windows,
		timers:        map[*time.Timer]struct{}{},
		purgeSpec:     specCachePurge,
		retentionSpec: specRetention,
		retentionAge:  retentionAge,
		alertsSpec:    specAlerts,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start регистрирует задачи и запускает cron; повторный вызов — ошибка
// (инстанс single-instance, п. 15.1). Невалидные расписания источников не
// роняют старт — источник пропускается с warn-логом и аудит-событием.
func (s *Scheduler) Start(ctx context.Context) error {
	if s.cron != nil {
		return fmt.Errorf("scheduler: уже запущен")
	}
	c := cron.New()
	if _, err := c.AddFunc(s.purgeSpec, func() { s.purgeCache(ctx) }); err != nil {
		return fmt.Errorf("scheduler: расписание прочистки кэша: %w", err)
	}
	if _, err := c.AddFunc(s.retentionSpec, func() { s.retention(ctx) }); err != nil {
		return fmt.Errorf("scheduler: расписание retention: %w", err)
	}
	if s.alertsFn != nil {
		if _, err := c.AddFunc(s.alertsSpec, func() { s.alerts(ctx) }); err != nil {
			return fmt.Errorf("scheduler: расписание алертов: %w", err)
		}
	}
	if s.backupSpec != "" {
		if _, err := c.AddFunc(s.backupSpec, func() { s.backup(ctx) }); err != nil {
			return fmt.Errorf("scheduler: расписание backup: %w", err)
		}
	}
	for _, src := range s.sources {
		if src.Schedule == "" {
			continue
		}
		name, spec := src.Name, src.Schedule
		if _, err := c.AddFunc(spec, func() { s.rescan(ctx, name) }); err != nil {
			// Не роняем старт: предупреждение + аудит, источник пропускается.
			s.log.Warn("scheduler: невалидное расписание источника, перескан не настроен",
				"source", name, "schedule", spec, "error", err)
			s.audit(ctx, "scheduler/invalid_schedule", "source:"+name,
				map[string]any{"source": name, "schedule": spec, "error": err.Error()})
			continue
		}
		s.log.Info("scheduler: периодический перескан настроен", "source", name, "schedule", spec)
	}
	s.cron = c
	c.Start()
	return nil
}

// Stop останавливает cron, дожидаясь завершения начатых задач
// (blueprint п. 13: плавная остановка), и снимает отложенные окном
// таймеры (п. 13.2).
func (s *Scheduler) Stop() {
	s.mu.Lock()
	for t := range s.timers {
		t.Stop()
	}
	s.timers = map[*time.Timer]struct{}{}
	s.mu.Unlock()
	if s.cron == nil {
		return
	}
	s.cron.Stop()
	s.cron = nil
}

// purgeCache — прочистка просроченных записей verdict_cache (п. 15.4).
func (s *Scheduler) purgeCache(ctx context.Context) {
	removed, err := s.st.CachePurgeExpired(ctx, s.nowFn())
	if err != nil {
		s.log.Error("scheduler: прочистка verdict_cache", "error", err)
		return
	}
	s.log.Info("scheduler: verdict_cache прочищен", "removed", removed)
	s.audit(ctx, "scheduler/cache_purge", "verdict_cache", map[string]any{"removed": removed})
}

// retention — автоочистка прогонов старше срока хранения (п. 15.4).
func (s *Scheduler) retention(ctx context.Context) {
	cutoff := s.nowFn().Add(-s.retentionAge)
	removed, err := s.st.PurgeScansOlderThan(ctx, cutoff)
	if err != nil {
		s.log.Error("scheduler: retention сканов", "error", err)
		return
	}
	s.log.Info("scheduler: retention выполнен", "removed_scans", removed, "cutoff", cutoff)
	s.audit(ctx, "scheduler/retention_purge", "scans",
		map[string]any{"removed_scans": removed, "cutoff": cutoff.UTC().Format(time.RFC3339)})
}

// rescan — периодический перескан источника по расписанию (п. 15). Профиль —
// default из detectors.yaml (пустая строка → решает runner). Ошибки старта
// (недоступность источника/LLM) — в лог: задача повторится по расписанию.
// Окно сканирования (п. 13.2): источник с scan_window, сработавший вне окна,
// — старт откладывается до начала окна (разовый таймер, аудит
// scheduler/scan_deferred).
func (s *Scheduler) rescan(ctx context.Context, source string) {
	if s.runner == nil {
		s.log.Warn("scheduler: перескан невозможен — runner не подключён", "source", source)
		return
	}
	if w, ok := s.windows[source]; ok {
		now := s.nowFn()
		if !w.Contains(now) {
			start := w.NextStart(now)
			d := start.Sub(now)
			s.log.Info("scheduler: перескан вне окна — отложен до начала окна (п. 13.2)",
				"source", source, "window_start", start.Format(time.RFC3339), "delay", d.Round(time.Second))
			s.audit(ctx, "scheduler/scan_deferred", "source:"+source, map[string]any{
				"source":       source,
				"window_start": start.UTC().Format(time.RFC3339),
				"delay_s":      int(d.Seconds()),
			})
			s.deferScan(ctx, source, d)
			return
		}
	}
	s.startScan(source)
}

// deferScan — разовый таймер до начала окна (п. 13.2). По срабатывании —
// повторный rescan (окно проверяется заново: часы могли сдвинуться); по
// Stop таймер снимается.
func (s *Scheduler) deferScan(ctx context.Context, source string, d time.Duration) {
	if d < 0 {
		d = 0
	}
	var t *time.Timer
	t = time.AfterFunc(d, func() {
		s.mu.Lock()
		delete(s.timers, t) // таймер уже отработал; при гонке со Stop — no-op
		s.mu.Unlock()
		s.rescan(ctx, source)
	})
	s.mu.Lock()
	s.timers[t] = struct{}{}
	s.mu.Unlock()
}

// startScan — немедленный старт перескана через runner (п. 15).
func (s *Scheduler) startScan(source string) {
	scanID, err := s.runner.Start(source, "", actor)
	if err != nil {
		s.log.Warn("scheduler: перескан не запустился", "source", source, "error", err)
		return
	}
	s.log.Info("scheduler: перескан запущен", "source", source, "scan_id", scanID)
}

// alerts — периодическая оценка правил алертинга (S6в, п. 17). Паника fn не
// роняет cron-цикл (recover) — одно сломанное правило не останавливает
// остальные фоновые задачи.
func (s *Scheduler) alerts(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("scheduler: паника в оценке алертов", "panic", r)
		}
	}()
	s.alertsFn(ctx)
}

// backup — периодическая онлайн-копия БД (S7б, п. 15.2). Каталог обязан
// существовать (конфиг оператора): неудача — тоже факт в аудите (ok/fail) —
// её видит правило backup_failed (п. 17).
func (s *Scheduler) backup(ctx context.Context) {
	out := filepath.Join(s.backupDir, store.BackupFilename(s.nowFn()))
	size, err := s.st.Backup(ctx, out)
	details := map[string]any{"path": out, "actor": "scheduler"}
	if err != nil {
		details["status"] = "fail"
		details["error"] = err.Error()
		s.log.Error("scheduler: backup неудачен", "path", out, "error", err)
	} else {
		details["status"] = "ok"
		details["bytes"] = size
		s.log.Info("scheduler: backup выполнен", "path", out, "bytes", size)
	}
	s.audit(ctx, "backup", "backup:"+out, details)
}

// audit — факт выполнения фоновой задачи в аудит-лог (п. 14.2: фоновые
// задачи журналируются). Задачи внутренние — категория CatAdmin. Ошибка
// записи — error-лог (задача уже выполнена; fail-closed не применим).
func (s *Scheduler) audit(ctx context.Context, action, target string, details map[string]any) {
	if err := s.st.AppendAudit(ctx, []audit.Event{{
		Actor: actor, Category: audit.CatAdmin, Action: action, Target: target,
		Details: details, TS: s.nowFn().UTC(),
	}}); err != nil {
		s.log.Error("scheduler: аудит задачи", "action", action, "error", err)
	}
}
