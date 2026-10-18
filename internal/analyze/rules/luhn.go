package rules

import (
	"github.com/DunchikVlad/zond/internal/verdict"
)

type luhnRecognizer struct{}

func (luhnRecognizer) ID() string           { return "rules/luhn" }
func (luhnRecognizer) Label() verdict.Label { return verdict.Label("CARD_NUMBER") }
func (luhnRecognizer) HasChecksum() bool    { return true }

// PAN банковских карт: 13–19 цифр, допустимы разделители " -",
// контрольная сумма Луна (blueprint п. 16.1).
func (luhnRecognizer) Match(v string) bool {
	if len(v) < 13 || len(v) > 23 {
		return false
	}
	digits := make([]byte, 0, 19)
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
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhnOK(digits)
}

func luhnOK(d []byte) bool {
	sum := 0
	parity := len(d) % 2
	for i := 0; i < len(d); i++ {
		n := int(d[i] - '0')
		if i%2 == parity {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}
