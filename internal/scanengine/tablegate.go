package scanengine

import "context"

// TableGate — блокирующий семафор конкурентной обработки таблиц внутри
// прогона (blueprint п. 13.2: max_concurrent_tables источника, default 2).
// Одна таблица занимает слот на всю обработку (схема → сэмплы колонок →
// коммит чекпоинта); внутри таблицы колонки по-прежнему последовательны
// (соединение драйвера не делится между воркерами). Захват ctx-aware:
// отмена прогона в ожидании слота не виснет.
type TableGate chan struct{}

// NewTableGate создаёт семафор ёмкости cap (<=0 — паника: дефолт
// спецификации подставляет вызывающий, п. 13.2).
func NewTableGate(cap int) TableGate {
	if cap <= 0 {
		panic("scanengine: NewTableGate: ёмкость должна быть > 0 (default — из конфига источника, п. 13.2)")
	}
	return make(TableGate, cap)
}

// Acquire занимает слот (блокируется при исчерпании); отмена ctx — ошибка.
func (g TableGate) Acquire(ctx context.Context) error {
	select {
	case g <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release освобождает слот. Вызывать ровно один раз после Acquire
// (defer-ом от обработки таблицы).
func (g TableGate) Release() { <-g }
