package rules

import (
	"strconv"
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// dateRecognizer — календарная дата (blueprint п. 16.1). Форматы:
// DD.MM.YYYY, DD/MM/YYYY, YYYY-MM-DD (ISO), DD-MM-YYYY. Реальная проверка
// диапазонов (месяц 1–12, день по месяцу/високосу). Лейбл DATE_TIME
// (DATE_OF_BIRTH определяется диапазоном/контекстом на кластерном слое).
type dateRecognizer struct{}

func (dateRecognizer) ID() string           { return "rules/date" }
func (dateRecognizer) Label() verdict.Label { return verdict.Label("DATE_TIME") }
func (dateRecognizer) HasChecksum() bool    { return false }

func (dateRecognizer) Match(v string) bool {
	v = strings.TrimSpace(v)
	var y, m, d int
	var ok bool
	switch {
	case strings.Count(v, ".") == 2: // DD.MM.YYYY
		y, m, d, ok = parseDMY(v, ".")
	case strings.Count(v, "/") == 2: // DD/MM/YYYY
		y, m, d, ok = parseDMY(v, "/")
	case strings.Count(v, "-") == 2: // ISO YYYY-MM-DD либо DD-MM-YYYY
		y, m, d, ok = parseDash(v)
	default:
		return false
	}
	if !ok {
		return false
	}
	return validDate(y, m, d)
}

// parseDMY разбирает "DD<sep>MM<sep>YYYY".
func parseDMY(v, sep string) (y, m, d int, ok bool) {
	p := strings.Split(v, sep)
	if len(p) != 3 || len(p[2]) != 4 {
		return 0, 0, 0, false
	}
	d, e1 := atoi(p[0])
	m, e2 := atoi(p[1])
	y, e3 := atoi(p[2])
	if e1 || e2 || e3 {
		return 0, 0, 0, false
	}
	return y, m, d, true
}

// parseDash: ISO (4-значный год впереди) либо DD-MM-YYYY.
func parseDash(v string) (y, m, d int, ok bool) {
	p := strings.Split(v, "-")
	if len(p) != 3 {
		return 0, 0, 0, false
	}
	if len(p[0]) == 4 { // ISO YYYY-MM-DD
		y, e1 := atoi(p[0])
		m, e2 := atoi(p[1])
		d, e3 := atoi(p[2])
		if e1 || e2 || e3 {
			return 0, 0, 0, false
		}
		return y, m, d, true
	}
	if len(p[2]) == 4 { // DD-MM-YYYY
		return parseDMY(v, "-")
	}
	return 0, 0, 0, false
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, true
		}
	}
	n, err := strconv.Atoi(s)
	return n, err != nil
}

// validDate — реальная проверка диапазонов (включая високосные годы).
func validDate(y, m, d int) bool {
	if y < 1900 || y > 2100 || m < 1 || m > 12 || d < 1 {
		return false
	}
	dim := daysInMonth(y, m)
	return d <= dim
}

func daysInMonth(y, m int) int {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeap(y) {
			return 29
		}
		return 28
	}
	return 0
}

func isLeap(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}
