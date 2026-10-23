// Тесты AttemptLimiter (blueprint п. 14, brute-force входа): блокировка
// после maxFails неудач в окне, сброс при успехе, истечение окна и
// блокировки. Время подменяется nowFn (white-box, пакет auth).
package auth

import (
	"testing"
	"time"
)

func TestLimiterBlocksAfterMaxFails(t *testing.T) {
	l := NewAttemptLimiter(3, time.Minute, time.Hour)
	for i := 0; i < 2; i++ {
		l.RecordFail("ip1")
	}
	if _, blocked := l.Blocked("ip1"); blocked {
		t.Fatal("блокировка раньше maxFails")
	}
	l.RecordFail("ip1")
	remaining, blocked := l.Blocked("ip1")
	if !blocked || remaining <= 0 {
		t.Fatalf("после maxFails должен быть блок: blocked=%v remaining=%v", blocked, remaining)
	}
	// Ключи независимы.
	if _, blocked := l.Blocked("ip2"); blocked {
		t.Fatal("блок ip1 не должен трогать ip2")
	}
}

func TestLimiterResetClears(t *testing.T) {
	l := NewAttemptLimiter(2, time.Minute, time.Hour)
	l.RecordFail("ip")
	l.Reset("ip")
	l.RecordFail("ip")
	if _, blocked := l.Blocked("ip"); blocked {
		t.Fatal("Reset должен сбрасывать счётчик")
	}
}

func TestLimiterWindowSliding(t *testing.T) {
	l := NewAttemptLimiter(2, 10*time.Minute, time.Hour)
	now := time.Now()
	l.nowFn = func() time.Time { return now }
	l.RecordFail("ip")
	now = now.Add(11 * time.Minute) // окно ушло — прошлая неудача не считается
	l.RecordFail("ip")
	if _, blocked := l.Blocked("ip"); blocked {
		t.Fatal("неудачи вне окна не должны блокировать")
	}
}

func TestLimiterBlockExpires(t *testing.T) {
	l := NewAttemptLimiter(1, time.Minute, 15*time.Minute)
	now := time.Now()
	l.nowFn = func() time.Time { return now }
	l.RecordFail("ip")
	if _, blocked := l.Blocked("ip"); !blocked {
		t.Fatal("должен быть блок")
	}
	now = now.Add(16 * time.Minute)
	if _, blocked := l.Blocked("ip"); blocked {
		t.Fatal("блокировка должна истечь")
	}
	// После истечения неудачи разрешены снова.
	l.RecordFail("ip")
	if _, blocked := l.Blocked("ip"); !blocked {
		t.Fatal("повторный блок после истечения")
	}
}

func TestLimiterDefaults(t *testing.T) {
	l := NewAttemptLimiter(0, 0, 0)
	if l.maxFails != LimiterMaxFails || l.window != LimiterWindow || l.blockFor != LimiterBlockFor {
		t.Fatalf("defaults: %+v", l)
	}
}
