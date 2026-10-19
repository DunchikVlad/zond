package agentproxy

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Тесты лимитов вызовов (blueprint п. 10.4): семафор конкурентности и
// глобальный rate-limit.

// TestGateLimitsPeakConcurrency — семафор ограничивает пиковую конкурентность:
// 6 вызовов через Gate(2, без rate-limit) к задержанному fake-агенту, пик в
// handler'е не превышает 2.
func TestGateLimitsPeakConcurrency(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	f.delay = 60 * time.Millisecond // вызов дольше, чем старт остальных горутин
	g := NewGate(2, 0)
	p := mustNew(t, testAgent(f.url()), WithGate(g))

	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = p.Classify(t.Context(), "String", []string{"+7 999 123-45-67", "+7 495 111-22-33"})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}
	f.mu.Lock()
	peak := f.maxConcurrent
	f.mu.Unlock()
	if peak > 2 {
		t.Fatalf("пиковая конкурентность %d > 2 (семафор п. 10.4)", peak)
	}
	if peak < 2 {
		t.Fatalf("пиковая конкурентность %d < 2 — семафор не параллелит вызовы", peak)
	}
}

// TestGateRateLimit — rate-limit 5 rps: 5 последовательных вызовов занимают
// не меньше 4 интервалов по 200 мс (≥0.8 с).
func TestGateRateLimit(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	g := NewGate(0, 5) // maxConcurrent → default 8
	p := mustNew(t, testAgent(f.url()), WithGate(g))

	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67", "+7 495 111-22-33"}); err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 800*time.Millisecond {
		t.Fatalf("rate-limit 5 rps не сдержал вызовы: 5 вызовов за %v (< 0.8 с)", elapsed)
	}
}

// TestGateNoRateLimit — rps=0: ожидания нет, 3 вызова проходят быстро.
func TestGateNoRateLimit(t *testing.T) {
	f := newFakeLLM(t, okAnswer)
	g := NewGate(8, 0)
	p := mustNew(t, testAgent(f.url()), WithGate(g))

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := p.Classify(t.Context(), "String", []string{"+7 999 123-45-67", "+7 495 111-22-33"}); err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("rps=0 не должен ждать: 3 вызова за %v", elapsed)
	}
}

// TestGateAcquireContextCancel — отмена контекста при занятом семафоре:
// ошибка, слот не теряется (следующий Acquire успешен).
func TestGateAcquireContextCancel(t *testing.T) {
	g := NewGate(1, 0)
	ctx, cancel := context.WithCancel(t.Context())
	g.sem <- struct{}{} // занять единственный слот извне
	cancel()
	if err := g.Acquire(ctx); err == nil {
		t.Fatal("Acquire с отменённым контекстом и занятым семафором должен вернуть ошибку")
	}
	select {
	case g.sem <- struct{}{}:
		t.Fatal("слот семафора потерян после прерванного Acquire")
	default:
	}
}

// TestGateDefaultMaxConcurrent — конструктор: maxConcurrent<=0 → default 8 (п. 10.4).
func TestGateDefaultMaxConcurrent(t *testing.T) {
	if cap(NewGate(0, 0).sem) != DefaultMaxConcurrent {
		t.Fatalf("default ёмкость семафора != %d", DefaultMaxConcurrent)
	}
	if cap(NewGate(-3, 0).sem) != DefaultMaxConcurrent {
		t.Fatalf("отрицательная ёмкость не заменена на default %d", DefaultMaxConcurrent)
	}
}
