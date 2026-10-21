// Тесты генератора эталонного eval-датасета (blueprint п. 16.6):
// детерминизм, квоты и покрытие лейблов, детект позитивов слоем 1
// (internal/analyze/rules), отвержение спуфов, однострочность значений.
package evalset

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// testLabels — реальная таксономия репозитория (порядок taxonomy.yaml).
func testLabels(t *testing.T) []verdict.Label {
	t.Helper()
	tax, err := config.LoadTaxonomy(filepath.Join("..", "..", "configs", "taxonomy.yaml"))
	if err != nil {
		t.Fatalf("LoadTaxonomy: %v", err)
	}
	labels := make([]verdict.Label, 0, len(tax.Labels))
	for _, l := range tax.Labels {
		labels = append(labels, verdict.Label(l.Name))
	}
	return labels
}

// testConfig — базовая конфигурация: фиксированный Now (манифест
// сравним побайтово), значения по умолчанию для Rows/Total.
func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Seed:            20261021,
		Rows:            20,
		Total:           1000,
		Labels:          testLabels(t),
		TaxonomyVersion: "1.0.0",
		Now:             time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
	}
}

// TestGenerateDeterministic — два вызова с одним seed → идентичный JSON
// колонок и манифеста (детерминизм PCG при фиксированном Now).
func TestGenerateDeterministic(t *testing.T) {
	cfg := testConfig(t)
	m1, cols1, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate #1: %v", err)
	}
	m2, cols2, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate #2: %v", err)
	}
	b1, err := json.Marshal(cols1)
	if err != nil {
		t.Fatalf("Marshal cols #1: %v", err)
	}
	b2, err := json.Marshal(cols2)
	if err != nil {
		t.Fatalf("Marshal cols #2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("Generate недетерминирован: JSON колонок различается")
	}
	mb1, _ := json.Marshal(m1)
	mb2, _ := json.Marshal(m2)
	if !bytes.Equal(mb1, mb2) {
		t.Fatal("Generate недетерминирован: JSON манифеста различается")
	}
}

// TestPositiveCountsAndCoverage — все лейблы присутствуют, суммы по
// Counts сходятся с Total, число колонок равно Total.
func TestPositiveCountsAndCoverage(t *testing.T) {
	cfg := testConfig(t)
	m, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cols) != cfg.Total {
		t.Fatalf("колонок %d, ожидалось %d", len(cols), cfg.Total)
	}
	if m.Total != len(cols) {
		t.Errorf("m.Total=%d ≠ len(cols)=%d", m.Total, len(cols))
	}
	sum := 0
	for _, n := range m.Counts.ByLabel {
		sum += n
	}
	if sum != cfg.Total {
		t.Errorf("сумма by_label=%d ≠ total=%d", sum, cfg.Total)
	}
	sum = 0
	for _, n := range m.Counts.ByKind {
		sum += n
	}
	if sum != cfg.Total {
		t.Errorf("сумма by_kind=%d ≠ total=%d", sum, cfg.Total)
	}
	for _, label := range cfg.Labels {
		if m.Counts.ByLabel[string(label)] == 0 {
			t.Errorf("лейбл %s отсутствует в датасете", label)
		}
	}
	// доля негативов ≈30% (позитивы ≥1 на лейбл)
	neg := m.Counts.ByKind[string(KindSpoof)] + m.Counts.ByKind[string(KindFreeText)] +
		m.Counts.ByKind[string(KindMixed)] + m.Counts.ByKind[string(KindPolymorphic)]
	if neg != 300 {
		t.Errorf("негативов %d, ожидалось 300 при Total=1000", neg)
	}
}

// detectorsByLabel — positive-колонки каких лейблов детектируются слоем 1
// и какими recognizer'ами (BANK_ACCOUNT — любой из двух: счёт или IBAN;
// DATE_OF_BIRTH — через dateRecognizer, его Label() — DATE_TIME).
func detectorsByLabel(t *testing.T) map[verdict.Label][]rules.Recognizer {
	t.Helper()
	byID := map[string]rules.Recognizer{}
	for _, r := range rules.Default() {
		byID[r.ID()] = r
	}
	for _, id := range []string{"rules/phone", "rules/email", "rules/inn", "rules/snils",
		"rules/passport", "rules/luhn", "rules/bank_account", "rules/iban",
		"rules/ip", "rules/date", "rules/uuid"} {
		if byID[id] == nil {
			t.Fatalf("recognizer %s отсутствует в rules.Default()", id)
		}
	}
	return map[verdict.Label][]rules.Recognizer{
		"PHONE":         {byID["rules/phone"]},
		"EMAIL":         {byID["rules/email"]},
		"TAX_ID":        {byID["rules/inn"]},
		"SNILS":         {byID["rules/snils"]},
		"PASSPORT_ID":   {byID["rules/passport"]},
		"CARD_NUMBER":   {byID["rules/luhn"]},
		"BANK_ACCOUNT":  {byID["rules/bank_account"], byID["rules/iban"]},
		"IP_ADDRESS":    {byID["rules/ip"]},
		"DATE_TIME":     {byID["rules/date"]},
		"DATE_OF_BIRTH": {byID["rules/date"]},
		"IDENTIFIER":    {byID["rules/uuid"]},
	}
}

// TestPositivesDetectableByRules — для каждой positive-колонки с
// recognizer'ом доля совпадений ≥0.9 (blueprint п. 16: эталонный датасет
// обязан детектиться regex-слоем).
func TestPositivesDetectableByRules(t *testing.T) {
	cfg := testConfig(t)
	_, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	detectors := detectorsByLabel(t)
	for _, col := range cols {
		if col.Kind != KindPositive {
			continue
		}
		recs, ok := detectors[col.Label]
		if !ok {
			continue // лейблы без recognizer'а (PERSON_NAME, ADDRESS, …)
		}
		matched := 0
		for _, v := range col.Values {
			for _, r := range recs {
				if r.Match(v) {
					matched++
					break
				}
			}
		}
		frac := float64(matched) / float64(len(col.Values))
		if frac < 0.9 {
			t.Errorf("колонка %s (%s/%s): детект %d/%d = %.2f < 0.9; примеры %v",
				col.ID, col.Label, col.Name, matched, len(col.Values), frac, col.Values[:3])
		}
	}
}

// TestSpoofsRejectedByRules — каждое значение каждой spoof-колонки НЕ
// матчится имитируемым recognizer'ом (IBAN-спуфы — ни счётом, ни IBAN).
func TestSpoofsRejectedByRules(t *testing.T) {
	cfg := testConfig(t)
	_, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	detectors := detectorsByLabel(t)
	spoofRecs := func(target string) []rules.Recognizer {
		switch target {
		case "TAX_ID":
			return detectors["TAX_ID"]
		case "SNILS":
			return detectors["SNILS"]
		case "CARD_NUMBER":
			return detectors["CARD_NUMBER"]
		case "BANK_ACCOUNT":
			return detectors["BANK_ACCOUNT"]
		default:
			return nil
		}
	}
	for _, col := range cols {
		if col.Kind != KindSpoof {
			continue
		}
		recs := spoofRecs(col.Spoofs)
		if recs == nil {
			t.Errorf("колонка %s: неизвестный spoof-таргет %q", col.ID, col.Spoofs)
			continue
		}
		for _, v := range col.Values {
			for _, r := range recs {
				if r.Match(v) {
					t.Errorf("колонка %s (spoof %s): значение %q матчится %s",
						col.ID, col.Spoofs, v, r.ID())
				}
			}
		}
	}
}

// TestValuesSingleLineAndNonEmpty — значения без \n/\r, непустые, число
// значений = Rows, ID уникальны.
func TestValuesSingleLineAndNonEmpty(t *testing.T) {
	cfg := testConfig(t)
	_, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ids := map[string]bool{}
	for _, col := range cols {
		if ids[col.ID] {
			t.Errorf("дублирующийся id %s", col.ID)
		}
		ids[col.ID] = true
		if len(col.Values) != cfg.Rows {
			t.Errorf("колонка %s: значений %d ≠ rows=%d", col.ID, len(col.Values), cfg.Rows)
		}
		for _, v := range col.Values {
			if v == "" {
				t.Errorf("колонка %s: пустое значение", col.ID)
			}
			if strings.ContainsAny(v, "\n\r") {
				t.Errorf("колонка %s: значение с переводом строки: %q", col.ID, v)
			}
		}
	}
}

// TestWriteRoundTrip — Write создаёт manifest.json и columns.jsonl,
// JSONL валиден и содержит ровно одну колонку на строку.
func TestWriteRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	m, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dir := t.TempDir()
	if err := Write(dir, m, cols); err != nil {
		t.Fatalf("Write: %v", err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	var m2 Manifest
	if err := json.Unmarshal(md, &m2); err != nil {
		t.Fatalf("manifest.json невалиден: %v", err)
	}
	if m2.Total != m.Total || m2.Seed != m.Seed {
		t.Errorf("манифест не сходится: got %+v, want %+v", m2, *m)
	}
	f, err := os.Open(filepath.Join(dir, "columns.jsonl"))
	if err != nil {
		t.Fatalf("columns.jsonl: %v", err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var c Column
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatalf("строка %d columns.jsonl невалидна: %v", n+1, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("чтение columns.jsonl: %v", err)
	}
	if n != len(cols) {
		t.Errorf("строк %d ≠ колонок %d", n, len(cols))
	}
}

// TestSmallTotal — масштабирование квот: при маленьком Total негативы не
// съедают позитивы (≥1 на лейбл), суммы сходятся.
func TestSmallTotal(t *testing.T) {
	cfg := testConfig(t)
	cfg.Total = 120
	m, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(cols) != 120 {
		t.Fatalf("колонок %d ≠ 120", len(cols))
	}
	for _, label := range cfg.Labels {
		if m.Counts.ByLabel[string(label)] == 0 {
			t.Errorf("лейбл %s без позитивов при Total=120", label)
		}
	}
	sum := 0
	for _, n := range m.Counts.ByKind {
		sum += n
	}
	if sum != 120 {
		t.Errorf("сумма by_kind=%d ≠ 120", sum)
	}
}

// TestDictionaryMinSizes — минимальные размеры словарей (blueprint п. 16.6).
func TestDictionaryMinSizes(t *testing.T) {
	cases := []struct {
		name string
		got  int
		min  int
	}{
		{"surnamesRU", len(surnamesRU), 40},
		{"firstNamesRU", len(firstNamesRU), 40},
		{"patronymicsRU", len(patronymicsRU), 25},
		{"citiesRU", len(citiesRU), 25},
		{"streetsRU", len(streetsRU), 30},
	}
	for _, c := range cases {
		if c.got < c.min {
			t.Errorf("%s: %d < %d", c.name, c.got, c.min)
		}
	}
}

// TestGeneratePerf — генерация 1000×20 укладывается в разумное время
// (бюджет CI: намного меньше 5 сек; обычно — миллисекунды).
func TestGeneratePerf(t *testing.T) {
	cfg := testConfig(t)
	start := time.Now()
	if _, _, err := Generate(cfg); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Generate занял %v > 5s", d)
	}
}

// TestGenerateErrors — валидация конфигурации.
func TestGenerateErrors(t *testing.T) {
	if _, _, err := Generate(Config{}); err == nil {
		t.Error("Generate без лейблов: ожидалась ошибка")
	}
	cfg := testConfig(t)
	cfg.Total = 3
	if _, _, err := Generate(cfg); err == nil {
		t.Error("Generate с Total < числа лейблов: ожидалась ошибка")
	}
}

// TestColumnOrderStable — позитивы идут первыми по лейблам, негативы —
// после; ID монотонны; виды идут блоками в фиксированном порядке.
func TestColumnOrderStable(t *testing.T) {
	cfg := testConfig(t)
	_, cols, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ord := map[string]int{"positive": 0, "spoof": 1, "free_text": 2, "mixed": 3, "polymorphic": 4}
	last := ""
	for i, col := range cols {
		wantID := colID(i)
		if col.ID != wantID {
			t.Fatalf("колонка %d: id %s ≠ %s", i, col.ID, wantID)
		}
		k := string(col.Kind)
		if ord[k] < ord[last] {
			t.Fatalf("виды не по порядку: %s после %s", k, last)
		}
		last = k
	}
}
