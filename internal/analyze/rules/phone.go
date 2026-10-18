package rules

import "github.com/DunchikVlad/zond/internal/verdict"

type phoneRecognizer struct{}

func (phoneRecognizer) ID() string           { return "rules/phone" }
func (phoneRecognizer) Label() verdict.Label { return verdict.Label("PHONE") }
func (phoneRecognizer) HasChecksum() bool    { return false }

// RU/E.164-практика: +7/8 + 10 цифр (11 всего) или 10 цифр с ведущей 9;
// допустимы разделители " -()", ведущий "+" только в начале.
func (phoneRecognizer) Match(v string) bool {
	if len(v) > 25 {
		return false
	}
	digits := make([]byte, 0, 12)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if i == 0 && c == '+' {
			continue
		}
		if c == ' ' || c == '-' || c == '(' || c == ')' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits = append(digits, c)
	}
	switch len(digits) {
	case 11:
		return digits[0] == '7' || digits[0] == '8'
	case 10:
		return digits[0] == '9'
	}
	return false
}
