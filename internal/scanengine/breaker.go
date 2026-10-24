package scanengine

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Пороги circuit breaker (blueprint п. 13.2, зафиксированы спецификацией):
// столько подряд failed-таблиц по причине source_overload останавливают
// прогон и ставят источник на паузу.
const (
	breakerConsecutiveFails = 5               // подряд failed с reason=source_overload
	breakerPause            = 5 * time.Minute // пауза источника после срабатывания
)

// SourcePausedError — скан отклонён: источник на паузе circuit breaker
// (п. 13.2). До Until повторные прогоны не начинаются.
type SourcePausedError struct {
	Source string
	Until  time.Time
}

func (e *SourcePausedError) Error() string {
	return fmt.Sprintf("источник %q на паузе circuit breaker до %s (перегрузка, п. 13.2)",
		e.Source, e.Until.UTC().Format(time.RFC3339))
}

// Breaker — circuit breaker по источникам (п. 13.2), состояние в памяти
// процесса. Один экземпляр на процесс serve (шарится между прогонами);
// CLI создаёт свой — в пределах одного прогона срабатывание корректно.
// Хранение в SQLite не требуется спецификацией: пауза краткоживущая (5 мин).
type Breaker struct {
	mu     sync.Mutex
	paused map[string]time.Time // source → until
}

// NewBreaker создаёт breaker с пустым состоянием.
func NewBreaker() *Breaker {
	return &Breaker{paused: map[string]time.Time{}}
}

// PausedErr возвращает ошибку паузы, если источник сейчас на паузе.
func (b *Breaker) PausedErr(source string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.paused[source]
	if !ok || now.After(until) {
		delete(b.paused, source)
		return nil
	}
	return &SourcePausedError{Source: source, Until: until}
}

// Trip ставит источник на паузу до now+pause. Идемпотентна в пределах паузы.
func (b *Breaker) Trip(source string, now time.Time, pause time.Duration) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	until := now.Add(pause)
	if prev, ok := b.paused[source]; ok && prev.After(until) {
		return prev
	}
	b.paused[source] = until
	return until
}

// ErrSourcePaused — удобная проверка для вызывающих (errors.As).
func ErrSourcePaused(err error) (*SourcePausedError, bool) {
	var p *SourcePausedError
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}
