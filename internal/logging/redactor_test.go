// Тесты redact middleware (blueprint п. 14.1): «метки-ловушки» — ни одна
// из них не должна встретиться в захваченном выводе логгера.
package logging

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Ловушки: пароль в DSN, Bearer-токен, admin-токен заголовком, явный
// секрет из env внутри сообщения и внутри атрибута.
const (
	trapDSN    = "clickhouse://ro:s3cr3t-pass@ch-host:9000/analytics"
	trapBearer = "Bearer sk-abcdef1234567890TESTKEY"
	trapAdmin  = "X-Admin-Token: adm1n-super-secret"
	trapEnv    = "LLM_VALUE_TRAP_key9988776655"
)

func trapRedactor() *SecretRedactor {
	return NewSecretRedactor(trapEnv, "s3cr3t-pass")
}

// TestSecretRedactorTraps — паттерны и явные значения маскируются полностью.
func TestSecretRedactorTraps(t *testing.T) {
	r := trapRedactor()
	cases := map[string]string{
		"dsn в сообщении":     "подключение: " + trapDSN + " ок",
		"bearer в атрибуте":   trapBearer,
		"admin заголовок":     trapAdmin,
		"env-секрет":          "ключ вызова: " + trapEnv,
		"частичное вхождение": "префикс-" + trapEnv + "-суффикс",
	}
	for name, in := range cases {
		out := r.Redact(in)
		for _, trap := range []string{"s3cr3t-pass", "sk-abcdef1234567890TESTKEY", "adm1n-super-secret", trapEnv} {
			if strings.Contains(out, trap) {
				t.Errorf("%s: ловушка %q осталась в %q", name, trap, out)
			}
		}
		if out == in {
			t.Errorf("%s: строка не изменилась", name)
		}
	}
}

// TestSecretRedactorKeepsClean — чистые строки проходят без изменений,
// короткие «секреты» (<6 символов) игнорируются.
func TestSecretRedactorKeepsClean(t *testing.T) {
	r := NewSecretRedactor("x", "abc", trapEnv)
	if got := r.Redact("обычное сообщение без секретов"); got != "обычное сообщение без секретов" {
		t.Errorf("чистая строка изменена: %q", got)
	}
	if got := r.Redact("значение abc"); got != "значение abc" {
		t.Errorf("короткое значение не должно маскироваться: %q", got)
	}
}

// TestLoggerAppliesRedact — ловушки в message и в строковых атрибутах не
// попадают в JSON-вывод логгера (п. 14.1: авто-тест сэмпла с ловушками).
func TestLoggerAppliesRedact(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "info", trapRedactor())
	log.Info("подключение к "+trapDSN,
		"authorization", trapBearer,
		"note", "вызываем агента с ключом "+trapEnv,
		"port", 9000,
	)
	out := buf.String()
	for _, trap := range []string{"s3cr3t-pass", "sk-abcdef1234567890TESTKEY", trapEnv} {
		if strings.Contains(out, trap) {
			t.Errorf("ловушка %q в логе: %s", trap, out)
		}
	}
	if !strings.Contains(out, "***") {
		t.Errorf("маскирование не отработало: %s", out)
	}
	if !strings.Contains(out, `"port":9000`) {
		t.Errorf("не-строковые атрибуты должны проходить: %s", out)
	}
	// correlation id — прозрачен для redact.
	buf.Reset()
	log2 := New(&buf, "info", trapRedactor())
	ctx := WithCorrelation(context.Background(), "cid-123")
	log2.InfoContext(ctx, "msg")
	if !strings.Contains(buf.String(), "cid-123") {
		t.Errorf("correlation id потерян: %s", buf.String())
	}
}
