// RateLimiter — общий rate-limit запросов API на субъекта (blueprint п. 11.2,
// S9-6). Token-bucket: capacity токенов, refill rate в секунду. Ключ — actor
// (sso:subject, token:id, admin-token, api). In-memory, потокобезопасен.
package api

import (
	"sync"
	"time"
)

// RateLimiterConfig — настройки rate-limit (п. 11.2 «настраивается»).
type RateLimiterConfig struct {
	// Capacity — максимум токенов в bucket (burst).
	Capacity int
	// RefillPerSec — скорость пополнения токенов в секунду.
	RefillPerSec float64
}

// DefaultRateLimiter — настройки по умолчанию (п. 11.2: 100 req/s на субъекта).
var DefaultRateLimiter = RateLimiterConfig{Capacity: 100, RefillPerSec: 100}

// RateLimiter — token-bucket rate limiter по ключу субъекта.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity int
	refill   float64
	nowFn    func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter создаёт limiter; nil config → default (100/100).
func NewRateLimiter(cfg *RateLimiterConfig) *RateLimiter {
	c := DefaultRateLimiter
	if cfg != nil {
		if cfg.Capacity > 0 {
			c.Capacity = cfg.Capacity
		}
		if cfg.RefillPerSec > 0 {
			c.RefillPerSec = cfg.RefillPerSec
		}
	}
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		capacity: c.Capacity,
		refill:   c.RefillPerSec,
		nowFn:    time.Now,
	}
}

// Allow проверяет, можно ли выполнить запрос от субъекта key.
// true — запрос разрешён (токен израсходован); false — отклонён (429).
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(r.capacity), last: r.nowFn()}
		r.buckets[key] = b
	}
	// Пополнение токенов по прошествии времени
	elapsed := r.nowFn().Sub(b.last).Seconds()
	b.tokens = min(float64(r.capacity), b.tokens+elapsed*r.refill)
	b.last = r.nowFn()
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Reset сбрасывает bucket субъекта (например, после успешной аутентификации).
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buckets, key)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
