// Redact middleware (blueprint п. 14.1): единая точка маскирования перед
// записью в операционный лог. Маскирует явно заданные значения секретов
// (env по конфигурации) и структурные паттерны (учётные данные в DSN/URI,
// заголовки Authorization / X-Admin-Token, Bearer/Basic). Авто-тест
// «меток-ловушек»: docs/validation — ни одна ловушка в захваченных логах.
package logging

import (
	"regexp"
	"strings"
)

// Паттерны маскирования — применяются всегда, без списка секретов.
var redactPatterns = []*regexp.Regexp{
	// Учётные данные в DSN/URI: scheme://user:pass@host → scheme://***@host
	// (пароли БД из ${ENV}-интерполяции и Vault-DSN).
	regexp.MustCompile(`(://[^/:@\s]+:)[^@\s/]+(@)`),
	// Заголовок Authorization (Bearer/Basic/др.): значение маскируется.
	regexp.MustCompile(`(?i)(authorization["':=\s]+(?:bearer|basic|digest)[\s"]+)[^"'\s,}]+`),
	// Схема Bearer/Basic/Digest как часть значения (атрибут authorization
	// без имени заголовка): «Bearer <token>» → «Bearer ***».
	regexp.MustCompile(`(?i)((?:^|["'\s])(?:bearer|basic|digest)[\s"]+)[A-Za-z0-9._\-=+/]{8,}`),
	// Заголовок X-Admin-Token как подстрока лога.
	regexp.MustCompile(`(?i)(x-admin-token["':=\s]+)[^"'\s,}]+`),
}

// SecretRedactor — Redactor на явных значениях + структурных паттернах.
// Значения короче 6 символов игнорируются (ложные срабатывания на «x»,
// «0» и т.п.). Не потокобезопасен при изменении списка после создания —
// заполняется на старте и дальше только читается.
type SecretRedactor struct {
	secrets []string
}

// NewSecretRedactor — redactor по явным значениям секретов (env токены,
// пароли, admin-токен и т.п.).
func NewSecretRedactor(secrets ...string) *SecretRedactor {
	seen := map[string]bool{}
	var kept []string
	for _, s := range secrets {
		if len(s) < 6 || seen[s] {
			continue
		}
		seen[s] = true
		kept = append(kept, s)
	}
	return &SecretRedactor{secrets: kept}
}

// Redact маскирует паттерны и явные значения; порядок: длинные значения
// первыми, чтобы частичные пересечения не оставляли хвосты.
func (r *SecretRedactor) Redact(s string) string {
	for _, re := range redactPatterns {
		s = re.ReplaceAllString(s, "${1}***${2}")
	}
	secrets := append([]string(nil), r.secrets...)
	// selection sort по убыванию длины — детерминировано и коротко.
	for i := 0; i < len(secrets); i++ {
		for j := i + 1; j < len(secrets); j++ {
			if len(secrets[j]) > len(secrets[i]) {
				secrets[i], secrets[j] = secrets[j], secrets[i]
			}
		}
	}
	for _, sec := range secrets {
		s = strings.ReplaceAll(s, sec, "***")
	}
	return s
}
