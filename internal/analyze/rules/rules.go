// Package rules — движок recognizer'ов слоя 1: regex по значениям +
// checksum-валидаторы (blueprint п. 7; ADR-0002).
// Этап 1: email/phone/ИНН/Luhn; полный набор RU-матчеров — этап 3
// (порт из angryscan-core, Apache-2.0 + NOTICE, риск R7).
package rules

import "github.com/DunchikVlad/zond/internal/verdict"

// Recognizer — детектор одного типа значений.
type Recognizer interface {
	ID() string // стабильный id для evidence (напр. "rules/inn")
	Label() verdict.Label
	Match(value string) bool
	HasChecksum() bool // true: Match уже включает валидацию контрольной суммы
}

// Match — результат recognizer'а по колонке.
type Match struct {
	RecognizerID string
	Label        verdict.Label
	HasChecksum  bool
	Matched      int
	Total        int
}

// Analyze прогоняет recognizer'ы по значениям колонки.
func Analyze(values []string, rs ...Recognizer) []Match {
	out := make([]Match, 0, len(rs))
	for _, r := range rs {
		m := Match{RecognizerID: r.ID(), Label: r.Label(), HasChecksum: r.HasChecksum(), Total: len(values)}
		for _, v := range values {
			if r.Match(v) {
				m.Matched++
			}
		}
		if m.Matched > 0 {
			out = append(out, m)
		}
	}
	return out
}

// Confidence — маппинг доли матчей на уверенность (blueprint п. 5.6):
// checksum совпал → 0.99 (конец пайплайна); ≥0.9 → 0.90; 0.5–0.9 → 0.70; <0.5 → 0.50.
func Confidence(m Match) float64 {
	if m.HasChecksum && m.Matched > 0 {
		return 0.99
	}
	if m.Total == 0 {
		return 0
	}
	f := float64(m.Matched) / float64(m.Total)
	switch {
	case f >= 0.9:
		return 0.90
	case f >= 0.5:
		return 0.70
	default:
		return 0.50
	}
}
