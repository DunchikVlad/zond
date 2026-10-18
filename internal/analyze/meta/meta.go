// Package meta — слой 0 каскада: классификация по имени колонки и словарю
// синонимов таксономии без чтения значений (blueprint п. 7; п. 5.6:
// словарь синонимов → 0.85, regex имени колонки → 0.60).
package meta

import (
	"regexp"
	"slices"
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

var tokenRe = regexp.MustCompile(`[a-zа-яё0-9]+`)

var namePatterns = []struct {
	re    *regexp.Regexp
	label verdict.Label
}{
	{regexp.MustCompile(`e.?mail|почта`), verdict.Label("EMAIL")},
	{regexp.MustCompile(`phone|(^|[^a-z])tel($|[^a-z])|моб|телефон`), verdict.Label("PHONE")},
	{regexp.MustCompile(`(^|[^a-z])inn($|[^a-z])|инн`), verdict.Label("TAX_ID")},
	{regexp.MustCompile(`(^|[^a-z])pan($|[^a-z])|card|карта`), verdict.Label("CARD_NUMBER")},
	{regexp.MustCompile(`passport|паспорт`), verdict.Label("PASSPORT_ID")},
	{regexp.MustCompile(`snils|снилс`), verdict.Label("SNILS")},
}

// Analyzer — слой 0 по словарю синонимов taxonomy.yaml.
type Analyzer struct {
	synonyms map[string][]string // label → токены имён колонок
}

// New строит анализатор из блока synonyms taxonomy.yaml (ADR-0004).
func New(synonyms map[string][]string) *Analyzer {
	cp := make(map[string][]string, len(synonyms))
	for k, v := range synonyms {
		cp[k] = append([]string(nil), v...)
	}
	return &Analyzer{synonyms: cp}
}

// ByName возвращает лейбл и confidence по имени колонки (п. 5.6).
// Сначала точное совпадение токена со словарём (0.85), затем regex имени (0.60).
func (a *Analyzer) ByName(column string) (verdict.Label, float64, bool) {
	nameToks := tokens(column)
	for label, dict := range a.synonyms {
		for _, tok := range dict {
			tt := tokens(tok)
			for _, single := range tt {
				if slices.Contains(nameToks, single) {
					return verdict.Label(label), 0.85, true
				}
			}
		}
	}
	lower := strings.ToLower(column)
	for _, p := range namePatterns {
		if p.re.MatchString(lower) {
			return p.label, 0.60, true
		}
	}
	return "", 0, false
}

func tokens(s string) []string {
	return tokenRe.FindAllString(strings.ToLower(s), -1)
}
