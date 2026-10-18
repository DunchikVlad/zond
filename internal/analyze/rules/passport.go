package rules

import (
	"github.com/DunchikVlad/zond/internal/verdict"
)

// passportRecognizer — паспорт РФ: серия 4 цифры + номер 6 цифр
// (blueprint п. 16.1). Форматная проверка (контрольной суммы у серии/номера нет);
// допустимы пробелы между серией и номером, внутри — нет.
type passportRecognizer struct{}

func (passportRecognizer) ID() string           { return "rules/passport" }
func (passportRecognizer) Label() verdict.Label { return verdict.Label("PASSPORT_ID") }
func (passportRecognizer) HasChecksum() bool    { return false }

func (passportRecognizer) Match(v string) bool {
	digits := make([]byte, 0, 10)
	spaces := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' {
			spaces++
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits = append(digits, c)
	}
	// только "SSSS NNNNNN" (не более 1 пробела) либо 10 цифр подряд
	if spaces > 1 {
		return false
	}
	if len(digits) != 10 {
		return false
	}
	// серия может начинаться с 0 (напр. 0315); номер (6 цифр) не нулевой
	numZero := true
	for i := 4; i < 10; i++ {
		if digits[i] != '0' {
			numZero = false
			break
		}
	}
	return !numZero
}
