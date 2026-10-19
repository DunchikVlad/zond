// Package fingerprint — отпечаток колонки (blueprint п. 7.6): признаки сэмпла,
// сходство колонок (основа кластеризации) и отпечаток пула значений для ключа
// кэша вердиктов (п. 10.5). Префикс/суффикс считаются по маскированным
// значениям — вызывающий обязан передать значения через mask (ADR-0010).
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Классы значений (п. 7.6 «классы значений: digit/alpha/mixed/empty»).
const (
	ClassDigit = "digit"
	ClassAlpha = "alpha"
	ClassMixed = "mixed"
	ClassEmpty = "empty"
)

// entropySampleCap — сколько значений участвуют в энтропии (детерминизм и
// ограничение стоимости на больших пулах).
const entropySampleCap = 1000

// FeatureSet — признаки отпечатка колонки (blueprint п. 7.6).
type FeatureSet struct {
	NativeType    string // нативный (развёрнутый) тип
	DominantClass string // digit|alpha|mixed|empty
	MinLen        int    // min/avg/max длина значений
	AvgLen        float64
	MaxLen        int
	NullFrac      float64 // доля null в сэмпле
	UniqueFrac    float64 // уникальность (distinct непустых / непустые)
	Entropy       float64 // энтропия символов сэмпла
	Prefix2       string  // первые 2 символа (по маскированным значениям)
	Suffix2       string  // последние 2 символа
}

// Compute вычисляет признаки отпечатка по значениям пула. masked должны быть
// уже маскированы (п. 7.6); total/nulls — счётчики пула (blueprint п. 5.2).
func Compute(nativeType string, masked []string, total, nulls int) FeatureSet {
	f := FeatureSet{NativeType: nativeType, MinLen: -1, DominantClass: ClassEmpty}
	if total > 0 {
		f.NullFrac = round4(float64(nulls) / float64(total))
	}
	var digit, alpha, mixed, empty, sumLen int
	seen := make(map[string]struct{})
	var sb strings.Builder
	prefixDone := false
	for _, v := range masked {
		if v == "" {
			empty++
			continue
		}
		// класс значения
		d, a := classOf(v)
		switch {
		case d && a:
			mixed++
		case d:
			digit++
		case a:
			alpha++
		}
		// длины
		l := len([]rune(v))
		sumLen += l
		if f.MinLen == -1 || l < f.MinLen {
			f.MinLen = l
		}
		if l > f.MaxLen {
			f.MaxLen = l
		}
		// уникальность
		if _, dup := seen[v]; !dup {
			seen[v] = struct{}{}
		}
		// префикс/суффикс — по первому непустому (детерминизм)
		if !prefixDone {
			r := []rune(v)
			f.Prefix2 = string(r[:min(2, len(r))])
			f.Suffix2 = string(r[max(0, len(r)-2):])
			prefixDone = true
		}
		// энтропия — по ограниченному числу значений
		if sb.Len() < entropySampleCap {
			sb.WriteString(v)
			sb.WriteByte(0)
		}
	}
	nonEmpty := len(masked) - empty
	if nonEmpty > 0 {
		f.AvgLen = round4(float64(sumLen) / float64(nonEmpty))
		f.UniqueFrac = round4(float64(len(seen)) / float64(nonEmpty))
	}
	f.DominantClass = dominantClass(digit, alpha, mixed, empty)
	f.Entropy = round4(shannon([]byte(sb.String())))
	return f
}

func classOf(v string) (digit, alpha bool) {
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= 'а' && r <= 'я' || r >= 'А' && r <= 'Я':
			alpha = true
		}
		if digit && alpha {
			return
		}
	}
	return
}

// dominantClass — детерминированный порядок при равенстве счётчиков.
func dominantClass(digit, alpha, mixed, empty int) string {
	type cls struct {
		name  string
		count int
	}
	classes := []cls{{ClassDigit, digit}, {ClassAlpha, alpha}, {ClassMixed, mixed}, {ClassEmpty, empty}}
	best := classes[0]
	for _, c := range classes[1:] {
		if c.count > best.count {
			best = c
		}
	}
	return best.name
}

// Similarity — доля совпавших признаков отпечатков (п. 7.6: кластер при
// совпадении нативного типа и ≥similarity остальных признаков). Нативный тип
// обязан совпадать, иначе сходство 0. Числовые признаки сравниваются по
// бакетам (округление), чтобы не требовать битового равенства.
func Similarity(a, b FeatureSet) float64 {
	if a.NativeType == "" || a.NativeType != b.NativeType {
		return 0
	}
	checks, matched := 0, 0
	eq := func(x bool) {
		checks++
		if x {
			matched++
		}
	}
	eq(a.DominantClass == b.DominantClass)
	eq(a.MinLen == b.MinLen)
	eq(a.MaxLen == b.MaxLen)
	eq(math.Round(a.AvgLen) == math.Round(b.AvgLen))
	eq(math.Round(a.NullFrac*10) == math.Round(b.NullFrac*10))
	eq(math.Round(a.UniqueFrac*10) == math.Round(b.UniqueFrac*10))
	eq(math.Round(a.Entropy*10) == math.Round(b.Entropy*10))
	eq(a.Prefix2 == b.Prefix2)
	eq(a.Suffix2 == b.Suffix2)
	if checks == 0 {
		return 0
	}
	return round4(float64(matched) / float64(checks))
}

// ID — стабильный идентификатор отпечатка (cluster_id, п. 7.6).
func ID(f FeatureSet) string {
	canonical := strings.Join([]string{
		f.NativeType, f.DominantClass,
		fmtInt(f.MinLen), fmtInt(f.MaxLen), fmtFloat(f.AvgLen),
		fmtFloat(f.NullFrac), fmtFloat(f.UniqueFrac), fmtFloat(f.Entropy),
		f.Prefix2, f.Suffix2,
	}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:8]) // 16 hex-символов достаточно для id кластера
}

// ValuesHash — отпечаток отсортированных уникальных усечённых значений
// (blueprint п. 10.5): часть ключа кэша вердиктов.
func ValuesHash(values []string) string {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	uniq := make([]string, 0, len(set))
	for v := range set {
		uniq = append(uniq, v)
	}
	sort.Strings(uniq)
	sum := sha256.Sum256([]byte(strings.Join(uniq, "\n")))
	return hex.EncodeToString(sum[:])
}

// shannon — энтропия Шеннона в битах на символ.
func shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
func fmtInt(v int) string      { return strconv.Itoa(v) }
func fmtFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', 4, 64)
}
