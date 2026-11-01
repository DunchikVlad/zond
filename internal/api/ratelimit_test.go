// Тесты RateLimiter (S9-6): token-bucket, Allow/Reset, границы.
package api

import (
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{Capacity: 3, RefillPerSec: 1})
	key := "test"

	// Первые 3 запроса — OK (burst)
	for i := 0; i < 3; i++ {
		if !rl.Allow(key) {
			t.Fatalf("Allow #%d = false, want true", i+1)
		}
	}
	// 4-й — отказ (bucket пуст)
	if rl.Allow(key) {
		t.Fatal("Allow #4 = true, want false")
	}
}

func TestRateLimiterRefill(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{Capacity: 2, RefillPerSec: 10})
	key := "test"

	rl.Allow(key)
	rl.Allow(key)
	if rl.Allow(key) {
		t.Fatal("bucket пуст")
	}

	// Ждём пополнения
	rl.nowFn = func() time.Time { return time.Now().Add(200 * time.Millisecond) }
	if !rl.Allow(key) {
		t.Fatal("после refill Allow = false")
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{Capacity: 1, RefillPerSec: 0.1})
	key := "test"

	rl.Allow(key)
	if rl.Allow(key) {
		t.Fatal("bucket пуст")
	}

	rl.Reset(key)
	if !rl.Allow(key) {
		t.Fatal("после Reset Allow = false")
	}
}

func TestRateLimiterDefault(t *testing.T) {
	rl := NewRateLimiter(nil)
	// Default: 100/100 — 100 запросов OK
	for i := 0; i < 100; i++ {
		if !rl.Allow("k") {
			t.Fatalf("Allow #%d = false", i)
		}
	}
	if rl.Allow("k") {
		t.Fatal("Allow #101 = true, want false")
	}
}

func TestRateLimiterSeparateKeys(t *testing.T) {
	rl := NewRateLimiter(&RateLimiterConfig{Capacity: 1, RefillPerSec: 0.1})
	rl.Allow("a")
	if rl.Allow("a") {
		t.Fatal("a: bucket пуст")
	}
	// Другой ключ — независим
	if !rl.Allow("b") {
		t.Fatal("b: Allow = false")
	}
}
