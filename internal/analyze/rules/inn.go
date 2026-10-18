package rules

import (
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

type innRecognizer struct{}

func (innRecognizer) ID() string           { return "rules/inn" }
func (innRecognizer) Label() verdict.Label { return verdict.Label("TAX_ID") }
func (innRecognizer) HasChecksum() bool    { return true }

// ИНН 10/12 цифр с контрольной суммой по спецификации ФНС (blueprint п. 16.1).
func (innRecognizer) Match(v string) bool {
	s := strings.TrimSpace(v)
	if len(s) != 10 && len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	d := make([]int, len(s))
	for i := range s {
		d[i] = int(s[i] - '0')
	}
	if len(d) == 10 {
		return innCheck(d[:9], d[9], innW10[:])
	}
	return innCheck(d[:10], d[10], innW11[:]) && innCheck(d[:11], d[11], innW12[:])
}

var innW10 = [...]int{2, 4, 10, 3, 5, 9, 4, 6, 8}
var innW11 = [...]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
var innW12 = [...]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}

func innCheck(digits []int, check int, w []int) bool {
	sum := 0
	for i, d := range digits {
		sum += d * w[i]
	}
	return sum%11%10 == check
}
