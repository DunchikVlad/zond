// Лимиты вызовов LLM (blueprint п. 10.4): семафор конкурентных вызовов
// (default 8) + глобальный rate-limit запросов/сек. Один вызов = один слот
// семафора (п. 10.3/10.4) — Gate разделяется между всеми прокси скана.
package agentproxy

import (
	"context"
	"sync"
	"time"
)

// DefaultMaxConcurrent — семафор конкурентных вызовов по умолчанию (п. 10.4).
const DefaultMaxConcurrent = 8

// Gate — семафор + rate-limiter для LLM-вызовов (blueprint п. 10.4).
// Не претендует на справедливость очереди: допускает maxConcurrent одновременно,
// между началами вызовов — интервал не менее 1/rps.
type Gate struct {
	sem chan struct{}
	// rate-limit: nextAllowed — время начала следующего разрешённого вызова.
	mu          sync.Mutex
	nextAllowed time.Time
	interval    time.Duration // 1/rps; 0 — без rate-limit
}

// NewGate собирает лимитер: maxConcurrent <= 0 → default 8 (п. 10.4);
// rps <= 0 — rate-limit не применяется.
func NewGate(maxConcurrent int, rps float64) *Gate {
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}
	g := &Gate{sem: make(chan struct{}, maxConcurrent)}
	if rps > 0 {
		g.interval = time.Duration(float64(time.Second) / rps)
	}
	return g
}

// Acquire занимает слот семафора и дожидается своей очереди по rate-limit.
// При отмене контекста возвращает ошибку; слот семафора не теряется
// (освобождается, если он был занят).
func (g *Gate) Acquire(ctx context.Context) error {
	select {
	case g.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := g.waitTurn(ctx); err != nil {
		<-g.sem // ожидание прервано — слот возвращаем (п. 10.4)
		return err
	}
	return nil
}

// waitTurn — глобальный rate-limit: резервирует слот времени не раньше
// nextAllowed и ждёт его наступления.
func (g *Gate) waitTurn(ctx context.Context) error {
	g.mu.Lock()
	now := time.Now()
	start := now
	if g.nextAllowed.After(now) {
		start = g.nextAllowed
	}
	g.nextAllowed = start.Add(g.interval)
	g.mu.Unlock()
	if !start.After(now) {
		return nil
	}
	t := time.NewTimer(start.Sub(now))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Release возвращает слот семафора; вызывается ровно один раз после успешного
// Acquire (обычно через defer).
func (g *Gate) Release() { <-g.sem }
