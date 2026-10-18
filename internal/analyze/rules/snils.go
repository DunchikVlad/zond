package rules

import (
	"github.com/DunchikVlad/zond/internal/verdict"
)

// snilsRecognizer — СНИЛС: 11 цифр, контрольная сумма (blueprint п. 16.1).
// Допустимы разделители " -" в форме "123-456-789 01".
type snilsRecognizer struct{}

func (snilsRecognizer) ID() string           { return "rules/snils" }
func (snilsRecognizer) Label() verdict.Label { return verdict.Label("SNILS") }
func (snilsRecognizer) HasChecksum() bool    { return true }

func (snilsRecognizer) Match(v string) bool {
	digits := make([]byte, 0, 11)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits = append(digits, c)
	}
	if len(digits) != 11 {
		return false
	}
	// контрольное число — последние 2 цифры; взвешенная сумма первых 9
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]-'0') * (9 - i)
	}
	var check int
	switch {
	case sum < 100:
		check = sum
	case sum == 100 || sum == 101:
		check = 0
	default:
		check = sum % 101
		if check == 100 {
			check = 0
		}
	}
	got := int(digits[9]-'0')*10 + int(digits[10]-'0')
	// номер из 9 одинаковых цифр и нулевой — недопустимы
	if digits[0] == '0' && allSameDigit(digits) {
		return false
	}
	return check == got
}

func allSameDigit(d []byte) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}
