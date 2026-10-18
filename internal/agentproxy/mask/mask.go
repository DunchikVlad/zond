// Package mask — маскирование значений перед отправкой в LLM (blueprint п. 10.2).
// Применяет маск-профиль по типу значения: PAN/телефон/ИНН-СНИЛС-паспорт-счёт/
// email/IP; прочее — плейсхолдеры фрагментов, найденных слоем 1, и усечение.
// Значения длиной ≤4 символов исключаются из пула (re-identification риск).
package mask

import (
	"regexp"
	"strings"
)

// Version — версия маск-профиля (входит в ключ кэша, п. 10.5).
// Меняется при любой правке правил маскирования.
const Version = "1"

// MinLen — минимальная длина значения, отправляемого агенту (п. 10.2).
const MinLen = 5

// Mask приводит значение к безопасному виду по угаданному типу.
// Возвращает ("", false), если значение короче MinLen (исключается из пула).
func Mask(v string) (string, bool) {
	if len(v) < MinLen {
		return "", false
	}
	switch {
	case looksLikePAN(v):
		return maskKeepEdges(v, 6, 4), true
	case looksLikeEmail(v):
		return maskEmail(v), true
	case looksLikeIP(v):
		return maskIP(v), true
	case looksLikeGovID(v): // ИНН/СНИЛС/паспорт/счёт — только цифры/разделители
		return maskKeepEdges(v, 1, 1), true
	case looksLikePhone(v):
		return maskPhone(v), true
	default:
		return Truncate(v, MaxStringChars), true
	}
}

// MaxStringChars — усечение длинных строк (п. 5.2, п. 10.2).
const MaxStringChars = 200

// Truncate усекает строку до n символов (по rune) с маркером.
func Truncate(v string, n int) string {
	r := []rune(v)
	if len(r) <= n {
		return v
	}
	return string(r[:n]) + "…"
}

var (
	panRe   = regexp.MustCompile(`^[0-9][0-9 \-]{11,22}[0-9]$`)
	phoneRe = regexp.MustCompile(`^\+?[0-9() \-]{9,}$`)
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	ipv4Re  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	govidRe = regexp.MustCompile(`^[0-9][0-9 \-]{8,18}[0-9]$`)
)

func looksLikePAN(v string) bool {
	d := countDigits(v)
	return d >= 13 && d <= 19 && panRe.MatchString(v)
}
func looksLikePhone(v string) bool {
	// телефон: ведущий '+' или характерные скобки, ≥10 цифр;
	// 10 цифр без '+' и скобок — это ИНН/СНИЛС (govid), не телефон
	if !phoneRe.MatchString(v) || countDigits(v) < 10 {
		return false
	}
	hasPlus := len(v) > 0 && v[0] == '+'
	return hasPlus || countDigits(v) >= 11 || strings.ContainsAny(v, "()")
}
func looksLikeEmail(v string) bool { return emailRe.MatchString(v) }
func looksLikeIP(v string) bool    { return ipv4Re.MatchString(v) || strings.Count(v, ":") >= 2 }
func looksLikeGovID(v string) bool {
	return govidRe.MatchString(v) && !looksLikePAN(v) && !looksLikePhone(v)
}

func countDigits(v string) int {
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			n++
		}
	}
	return n
}

// maskKeepEdges оставляет первые a и последние b цифр, середина → '*',
// длина и разделители сохраняются (п. 10.2: PAN 6+4, ИНН/счёт 1+1).
func maskKeepEdges(v string, a, b int) string {
	digits := 0
	for i := 0; i < len(v); i++ {
		if v[i] >= '0' && v[i] <= '9' {
			digits++
		}
	}
	out := []byte(v)
	seen := 0
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c < '0' || c > '9' {
			continue // разделитель сохраняется
		}
		seen++
		if seen > a && seen <= digits-b {
			out[i] = '*'
		}
	}
	return string(out)
}

// maskPhone: код страны/города и последние 2 цифры (п. 10.2: +7 *** *** 12 34).
func maskPhone(v string) string {
	d := countDigits(v)
	if d < 3 {
		return maskKeepEdges(v, 1, 1)
	}
	return maskKeepEdges(v, d-4, 2)
}

// maskEmail: локальная часть — первый символ + "***"; домен открыт.
func maskEmail(v string) string {
	at := strings.IndexByte(v, '@')
	if at <= 0 {
		return Truncate(v, MaxStringChars)
	}
	local := v[:at]
	return local[:1] + "***" + v[at:]
}

// maskIP: последний октет скрыт (IPv4); IPv6 — последний сегмент.
func maskIP(v string) string {
	if i := strings.LastIndexByte(v, '.'); i >= 0 {
		return v[:i+1] + "*"
	}
	if i := strings.LastIndexByte(v, ':'); i >= 0 {
		return v[:i+1] + "*"
	}
	return v
}
