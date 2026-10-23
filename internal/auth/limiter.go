// AttemptLimiter — rate-limit неудачных попыток входа (blueprint п. 14,
// brute-force admin-токена): после maxFails неудачных аутентификаций в
// скользящем окне window ключ (обычно IP клиента) блокируется на blockFor.
// In-memory, потокобезопасен; для single-instance-режима (п. 15.1) этого
// достаточно. Успешная аутентификация сбрасывает счётчик (Reset).
package auth

import (
	"sync"
	"time"
)

// Defaults (п. 14 «настраивается» — значения по умолчанию инкремента S7г;
// внешняя конфигурация — при необходимости отдельным инкрементом).
const (
	LimiterMaxFails   = 5
	LimiterWindow     = 10 * time.Minute
	LimiterBlockFor   = 15 * time.Minute
	limiterSweepEvery = 100 // грубая уборка мёртвых записей раз в N операций
)

// AttemptLimiter — счётчик неудач и блокировок по ключу.
type AttemptLimiter struct {
	mu           sync.Mutex
	fails        map[string][]time.Time // key → метки неудач в окне (отсортированы)
	blockedUntil map[string]time.Time
	maxFails     int
	window       time.Duration
	blockFor     time.Duration
	nowFn        func() time.Time
	ops          int
}

// NewAttemptLimiter — лимитер с параметрами; неположительные значения
// заменяются Defaults.
func NewAttemptLimiter(maxFails int, window, blockFor time.Duration) *AttemptLimiter {
	if maxFails <= 0 {
		maxFails = LimiterMaxFails
	}
	if window <= 0 {
		window = LimiterWindow
	}
	if blockFor <= 0 {
		blockFor = LimiterBlockFor
	}
	return &AttemptLimiter{
		fails: map[string][]time.Time{}, blockedUntil: map[string]time.Time{},
		maxFails: maxFails, window: window, blockFor: blockFor, nowFn: time.Now,
	}
}

// Blocked — заблокирован ли ключ сейчас; второе значение — остаток
// блокировки (>0 означает, что запрос надо отклонить без проверки).
func (l *AttemptLimiter) Blocked(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.blockedUntil[key]
	if !ok {
		return 0, false
	}
	now := l.nowFn()
	if !now.Before(until) {
		delete(l.blockedUntil, key)
		return 0, false
	}
	return until.Sub(now), true
}

// RecordFail — учесть неудачную аутентификацию; при превышении maxFails
// в окне ключ блокируется на blockFor (повторные неудачи в блокировке
// счётчик не двигают — блокировка и есть цель).
func (l *AttemptLimiter) RecordFail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ops++
	if l.ops%limiterSweepEvery == 0 {
		l.sweepLocked()
	}
	if until, ok := l.blockedUntil[key]; ok && l.nowFn().Before(until) {
		return
	}
	now := l.nowFn()
	cut := now.Add(-l.window)
	marks := l.fails[key]
	kept := marks[:0] // метки старше окна отсекаем in-place
	for _, m := range marks {
		if m.After(cut) {
			kept = append(kept, m)
		}
	}
	kept = append(kept, now)
	l.fails[key] = kept
	if len(kept) >= l.maxFails {
		l.blockedUntil[key] = now.Add(l.blockFor)
		delete(l.fails, key)
	}
}

// Reset — успешная аутентификация: счётчик неудач и блокировка снимаются.
func (l *AttemptLimiter) Reset(key string) {
	l.mu.Lock()
	delete(l.fails, key)
	delete(l.blockedUntil, key)
	l.mu.Unlock()
}

// sweepLocked — уборка просроченных блокировок и пустых счётчиков.
func (l *AttemptLimiter) sweepLocked() {
	now := l.nowFn()
	for k, until := range l.blockedUntil {
		if !now.Before(until) {
			delete(l.blockedUntil, k)
		}
	}
	for k, marks := range l.fails {
		cut := now.Add(-l.window)
		kept := marks[:0]
		for _, m := range marks {
			if m.After(cut) {
				kept = append(kept, m)
			}
		}
		if len(kept) == 0 {
			delete(l.fails, k)
		} else {
			l.fails[k] = kept
		}
	}
}
