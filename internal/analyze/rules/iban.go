package rules

import (
	"github.com/DunchikVlad/zond/internal/verdict"
)

// ibanRecognizer — IBAN: ISO 13616, контрольная сумма mod-97 (blueprint п. 16.1).
// Формат: 2 буквы страны + 2 контрольные цифры + BBAN (до 30 символов).
type ibanRecognizer struct{}

func (ibanRecognizer) ID() string           { return "rules/iban" }
func (ibanRecognizer) Label() verdict.Label { return verdict.Label("BANK_ACCOUNT") }
func (ibanRecognizer) HasChecksum() bool    { return true }

func (ibanRecognizer) Match(v string) bool {
	// убираем пробелы (IBAN часто пишут группами по 4)
	b := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == ' ' {
			continue
		}
		b = append(b, v[i])
	}
	if len(b) < 15 || len(b) > 34 {
		return false
	}
	// 2 буквы + 2 цифры
	if !isUpperLetter(b[0]) || !isUpperLetter(b[1]) || !isDigit(b[2]) || !isDigit(b[3]) {
		return false
	}
	for i := 4; i < len(b); i++ {
		if !isUpperLetter(b[i]) && !isDigit(b[i]) {
			return false
		}
	}
	// mod-97: перестановка BBAN+код страны+контроль → остаток 1
	return ibanMod97(b) == 1
}

// ibanMod97 считает остаток от деления численного представления
// (переставленного IBAN) на 97. Буквы → числа: A=10 … Z=35.
func ibanMod97(b []byte) int {
	// перестановка: символы [4:] + [0:4]
	rem := 0
	process := func(c byte) {
		switch {
		case isDigit(c):
			rem = (rem*10 + int(c-'0')) % 97
		case isUpperLetter(c):
			n := int(c-'A') + 10
			rem = (rem*100 + n) % 97
		}
	}
	for i := 4; i < len(b); i++ {
		process(b[i])
	}
	for i := 0; i < 4; i++ {
		process(b[i])
	}
	return rem
}

func isDigit(c byte) bool       { return c >= '0' && c <= '9' }
func isUpperLetter(c byte) bool { return c >= 'A' && c <= 'Z' }
