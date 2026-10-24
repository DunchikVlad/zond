package config

import (
	"fmt"
	"strings"
	"time"
)

// Window — окно сканирования источника (blueprint п. 13.2, scan_window):
// локальное время инстанса, формат "HH:MM-HH:MM". Старт перескана вне окна
// откладывается шедулером до начала окна. Окно через полночь
// ("22:00-02:00") поддерживается. Пустое окно (start == end) двусмысленно
// (0 ч или 24 ч) — отклоняется при загрузке (fail-fast, ADR-0009).
type Window struct {
	startMin int // минуты от полуночи (локальное время)
	endMin   int // конец окна исключителен: 06:00 уже вне окна "02:00-06:00"
}

// ParseWindow парсит scan_window ("HH:MM-HH:MM", строгий формат с ведущим
// нулём). Локальное время инстанса — как у cron-расписаний шедулера.
func ParseWindow(s string) (Window, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return Window{}, fmt.Errorf("окно %q не в формате HH:MM-HH:MM (п. 13.2)", s)
	}
	start, err := parseHHMM(parts[0])
	if err != nil {
		return Window{}, fmt.Errorf("окно %q: начало: %w", s, err)
	}
	end, err := parseHHMM(parts[1])
	if err != nil {
		return Window{}, fmt.Errorf("окно %q: конец: %w", s, err)
	}
	if start == end {
		return Window{}, fmt.Errorf("окно %q двусмысленно (начало == конец): задайте непустой интервал", s)
	}
	return Window{startMin: start, endMin: end}, nil
}

// parseHHMM — строгий "HH:MM" (ровно 5 символов, двоеточие, диапазоны
// часов/минут проверяет time.Parse по layout 15:04).
func parseHHMM(p string) (int, error) {
	if len(p) != 5 || p[2] != ':' {
		return 0, fmt.Errorf("%q не в формате HH:MM", p)
	}
	t, err := time.Parse("15:04", p)
	if err != nil {
		return 0, fmt.Errorf("%q не в формате HH:MM", p)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// Contains — now (локальное время инстанса) внутри окна? Конец окна
// исключителен. Окно через полночь (start > end) покрывает конец суток и
// начало следующих.
func (w Window) Contains(now time.Time) bool {
	m := now.Hour()*60 + now.Minute()
	if w.startMin < w.endMin {
		return m >= w.startMin && m < w.endMin
	}
	return m >= w.startMin || m < w.endMin
}

// NextStart — ближайший момент начала окна (локальное время инстанса).
// Если now внутри окна — now (окно уже открыто). DST-переходы не
// учитываются: полночь + 24ч (окно ночное, погрешность часа терпима).
func (w Window) NextStart(now time.Time) time.Time {
	if w.Contains(now) {
		return now
	}
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	start := midnight.Add(time.Duration(w.startMin) * time.Minute)
	if !start.After(now) {
		start = start.Add(24 * time.Hour)
	}
	return start
}
