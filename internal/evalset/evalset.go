// Package evalset — генератор эталонного eval-датасета (blueprint п. 16.6,
// п. 16 п. 6): колонки × лейблы таксономии, включая негативы — PII внутри
// свободного текста, похожие значения с неверными контрольными суммами
// (спуфы), mixed-типы и полиморфные коллекции Mongo. Детерминизм: при
// фиксированном Seed выдача побайтово идентична (math/rand/v2, PCG).
//
// Формат выдачи: manifest.json (сводка, квоты, версии) + columns.jsonl
// (одна колонка — одна строка). Запись — Write.
package evalset

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// datasetVersion — semver датасета (ADR: patch — правка генераторов,
// minor — новые виды колонок, major — смена формата).
const datasetVersion = "1.0.0"

// Kind — вид колонки датасета.
type Kind string

const (
	KindPositive    Kind = "positive"    // чистые значения ожидаемого лейбла
	KindSpoof       Kind = "spoof"       // формат верный, контрольная сумма НЕВЕРНАЯ (ложняк)
	KindFreeText    Kind = "free_text"   // свободный текст со встроенным PII (ожид. FREE_TEXT)
	KindMixed       Kind = "mixed"       // Mongo mixed-типы (скаляры разных типов)
	KindPolymorphic Kind = "polymorphic" // Mongo полиморфные коллекции (массивы/документы)
)

// Column — одна колонка эталонного датасета: ожидаемый лейбл, вид и значения.
type Column struct {
	ID       string          `json:"id"`    // "col-0000" …, уникальные, порядок стабилен
	Name     string          `json:"name"`  // реалистичное имя колонки (EN/RU)
	Label    verdict.Label   `json:"label"` // ожидаемый лейбл таксономии
	Kind     Kind            `json:"kind"`
	Spoofs   string          `json:"spoofs,omitempty"`   // KindSpoof: имитируемый лейбл (таксономия)
	Embedded []verdict.Label `json:"embedded,omitempty"` // KindFreeText: какие PII встроены
	Values   []string        `json:"values"`             // все значения однострочные (без \n, без \r)
}

// Manifest — сводка датасета (manifest.json).
type Manifest struct {
	Dataset   string `json:"dataset"` // semver датасета
	Seed      int64  `json:"seed"`
	Rows      int    `json:"rows"`      // значений на колонку
	Total     int    `json:"total"`     // колонок всего
	Taxonomy  string `json:"taxonomy"`  // версия taxonomy.yaml
	Generated string `json:"generated"` // UTC RFC3339
	Counts    Counts `json:"counts"`    // по лейблам и по видам
}

// Counts — число колонок по лейблам и по видам.
type Counts struct {
	ByLabel map[string]int `json:"by_label"`
	ByKind  map[string]int `json:"by_kind"`
}

// Config — параметры генерации.
type Config struct {
	Seed            int64           // детерминизм выдачи
	Rows            int             // значений на колонку (default 20)
	Total           int             // колонок всего, positives + negatives (default 1000)
	Labels          []verdict.Label // порядок как в taxonomy.yaml (обязательно, непусто)
	TaxonomyVersion string          // версия taxonomy.yaml → манифест
	Now             time.Time       // время в манифест; если zero — time.Now().UTC()
}

// negKind — фиксированный порядок негативных квот (8 слотов): спуфы
// (TAX_ID, SNILS, CARD_NUMBER, BANK_ACCOUNT-IBAN), free_text, mixed с
// доминантой, mixed chaos, полиморфные коллекции.
type negKind int

const (
	negSpoofTax negKind = iota
	negSpoofSnils
	negSpoofCard
	negSpoofBank
	negFreeText
	negMixedDominant
	negMixedChaos
	negPoly
	negKinds
)

// negWeights — базовые квоты при Total=1000 (сумма 300 = 30% негативов).
var negWeights = [negKinds]int{
	negSpoofTax:      30,
	negSpoofSnils:    30,
	negSpoofCard:     30,
	negSpoofBank:     20,
	negFreeText:      80,
	negMixedDominant: 40,
	negMixedChaos:    20,
	negPoly:          50,
}

const negWeightSum = 300

// Generate — детерминированная генерация датасета (blueprint п. 16.6):
// сначала positives по лейблам (в порядке cfg.Labels), затем negatives
// в фиксированном порядке: spoofs (TAX_ID, SNILS, CARD_NUMBER,
// BANK_ACCOUNT), free_text, mixed, polymorphic. ID колонок "col-%04d".
func Generate(cfg Config) (*Manifest, []Column, error) {
	if len(cfg.Labels) == 0 {
		return nil, nil, errors.New("evalset: Labels обязателен (порядок из taxonomy.yaml)")
	}
	rows := cfg.Rows
	if rows <= 0 {
		rows = 20
	}
	total := cfg.Total
	if total <= 0 {
		total = 1000
	}
	if total < len(cfg.Labels) {
		return nil, nil, fmt.Errorf("evalset: Total=%d меньше числа лейблов %d", total, len(cfg.Labels))
	}
	now := cfg.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rng := rand.New(rand.NewPCG(uint64(cfg.Seed), uint64(cfg.Seed>>32)^0x9E3779B9))
	g := &generator{rng: rng, rows: rows}

	neg := splitNegatives(total, len(cfg.Labels))
	negTotal := 0
	for _, n := range neg {
		negTotal += n
	}
	positives := total - negTotal

	var cols []Column
	idx := 0

	// Positives: максимально равное распределение, первые positives % len —
	// по одной доп. колонке.
	base, extra := positives/len(cfg.Labels), positives%len(cfg.Labels)
	for i, label := range cfg.Labels {
		n := base
		if i < extra {
			n++
		}
		for j := 0; j < n; j++ {
			cols = append(cols, Column{
				ID:     colID(idx),
				Name:   g.positiveName(label),
				Label:  label,
				Kind:   KindPositive,
				Values: g.positiveValues(label),
			})
			idx++
		}
	}

	// Negatives в фиксированном порядке.
	for i := 0; i < neg[negSpoofTax]; i++ {
		cols = append(cols, g.spoofColumn(colID(idx), "TAX_ID"))
		idx++
	}
	for i := 0; i < neg[negSpoofSnils]; i++ {
		cols = append(cols, g.spoofColumn(colID(idx), "SNILS"))
		idx++
	}
	for i := 0; i < neg[negSpoofCard]; i++ {
		cols = append(cols, g.spoofColumn(colID(idx), "CARD_NUMBER"))
		idx++
	}
	for i := 0; i < neg[negSpoofBank]; i++ {
		cols = append(cols, g.spoofColumn(colID(idx), "BANK_ACCOUNT"))
		idx++
	}
	for i := 0; i < neg[negFreeText]; i++ {
		emb := embeddedCycle[i%len(embeddedCycle)]
		cols = append(cols, Column{
			ID:       colID(idx),
			Name:     pickName(g.rng, freeTextNames),
			Label:    "FREE_TEXT",
			Kind:     KindFreeText,
			Embedded: []verdict.Label{emb},
			Values:   g.freeTextValues(emb),
		})
		idx++
	}
	for i := 0; i < neg[negMixedDominant]; i++ {
		label := dominantLabels[i%len(dominantLabels)]
		cols = append(cols, Column{
			ID:     colID(idx),
			Name:   pickName(g.rng, mixedNames),
			Label:  label,
			Kind:   KindMixed,
			Values: g.mixedDominantValues(label),
		})
		idx++
	}
	for i := 0; i < neg[negMixedChaos]; i++ {
		cols = append(cols, Column{
			ID:     colID(idx),
			Name:   pickName(g.rng, mixedNames),
			Label:  "UNKNOWN",
			Kind:   KindMixed,
			Values: g.chaosValues(),
		})
		idx++
	}
	for i := 0; i < neg[negPoly]; i++ {
		cols = append(cols, Column{
			ID:     colID(idx),
			Name:   pickName(g.rng, polyNames),
			Label:  "UNKNOWN",
			Kind:   KindPolymorphic,
			Values: g.polyValues(),
		})
		idx++
	}

	m := &Manifest{
		Dataset:   datasetVersion,
		Seed:      cfg.Seed,
		Rows:      rows,
		Total:     len(cols),
		Taxonomy:  cfg.TaxonomyVersion,
		Generated: now.UTC().Format(time.RFC3339),
		Counts:    countColumns(cols),
	}
	return m, cols, nil
}

// splitNegatives — квоты негативов: 30% от Total, пропорционально базовым
// весам (округление вниз, остаток — в free_text). При маленьких Total
// квоты режутся пропорционально, минимум 1 на вид (пока бюджет позволяет),
// positives ≥ 1 на лейбл гарантируется клэмпом бюджета.
func splitNegatives(total, nLabels int) [negKinds]int {
	budget := total * 3 / 10
	if maxNeg := total - nLabels; budget > maxNeg {
		budget = maxNeg // positives ≥ 1 на лейбл
	}
	if budget < 0 {
		budget = 0
	}
	var raw [negKinds]int
	s := 0
	for i := 0; i < int(negKinds); i++ {
		raw[i] = budget * negWeights[i] / negWeightSum
		s += raw[i]
	}
	// минимум 1 на вид — в фиксированном порядке, пока бюджет позволяет
	for i := 0; i < int(negKinds) && s < budget; i++ {
		if raw[i] == 0 {
			raw[i] = 1
			s++
		}
	}
	raw[negFreeText] += budget - s // остаток добираем в free_text
	return raw
}

// spoofColumn — колонка-спуф: имитирует лейбл target (поле Spoofs), но
// ground truth — UNKNOWN (значение формально не является ИНН/СНИЛС/картой).
func (g *generator) spoofColumn(id string, target verdict.Label) Column {
	return Column{
		ID:     id,
		Name:   pickName(g.rng, spoofNames[target]),
		Label:  "UNKNOWN",
		Kind:   KindSpoof,
		Spoofs: string(target),
		Values: g.spoofValues(target),
	}
}

// colID — стабильный идентификатор колонки.
func colID(i int) string { return fmt.Sprintf("col-%04d", i) }

// countColumns — сводка по лейблам и видам.
func countColumns(cols []Column) Counts {
	c := Counts{ByLabel: map[string]int{}, ByKind: map[string]int{}}
	for _, col := range cols {
		c.ByLabel[string(col.Label)]++
		c.ByKind[string(col.Kind)]++
	}
	return c
}

// positiveName — «говорящее» имя (≈70%) или нейтральное (≈30%).
func (g *generator) positiveName(label verdict.Label) string {
	if g.rng.IntN(100) < 30 {
		return g.neutralName(label)
	}
	return pickName(g.rng, columnNames[label])
}

// neutralName — нейтральное имя колонки без семантики лейбла.
func (g *generator) neutralName(label verdict.Label) string {
	switch g.rng.IntN(3) {
	case 0:
		return fmt.Sprintf("col_%s_%03d", strings.ToLower(string(label)), g.rng.IntN(1000))
	case 1:
		return fmt.Sprintf("field%d", g.rng.IntN(100))
	default:
		return fmt.Sprintf("attr_x%d", g.rng.IntN(100))
	}
}

// pickName — случайный элемент пула имён.
func pickName(rng *rand.Rand, pool []string) string {
	return pool[rng.IntN(len(pool))]
}

// Write — manifest.json (indent) + columns.jsonl (по одной колонке на строку)
// в каталог dir (mkdir -p). Перезаписывает существующие файлы.
func Write(dir string, m *Manifest, cols []Column) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("evalset: каталог %s: %w", dir, err)
	}
	md, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("evalset: манифест: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(md, '\n'), 0o644); err != nil {
		return fmt.Errorf("evalset: manifest.json: %w", err)
	}
	var buf bytes.Buffer
	for i := range cols {
		line, err := json.Marshal(cols[i])
		if err != nil {
			return fmt.Errorf("evalset: колонка %s: %w", cols[i].ID, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "columns.jsonl"), buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("evalset: columns.jsonl: %w", err)
	}
	return nil
}

// SortByKind — ключи ByKind в лексикографическом порядке (стабильный вывод CLI).
func (m *Manifest) SortByKind() []string {
	keys := make([]string, 0, len(m.Counts.ByKind))
	for k := range m.Counts.ByKind {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
