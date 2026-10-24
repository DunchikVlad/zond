package benchlab

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/DunchikVlad/zond/internal/analyze/rules"
)

func newTestRNG(seed int64) *rand.Rand {
	return rand.New(rand.NewPCG(uint64(seed), uint64(seed>>1)|1))
}

func TestNegativeInvariant(t *testing.T) {
	// Ни одно негативное значение не должно матчиться ни одним recognizer'ом.
	recs := rules.Default()
	const n = 20000
	values := make([]string, n)
	for i := range values {
		values[i] = negatives[i%len(negatives)](newTestRNG(int64(i)))
	}
	for _, m := range rules.Analyze(values, recs...) {
		t.Fatalf("негатив сматчился recognizer'ом %s: %d из %d", m.RecognizerID, m.Matched, m.Total)
	}
}

func TestPositiveCoverage(t *testing.T) {
	// Каждый генератор выдаёт значения, на 100% матчащиеся «своим»
	// recognizer'ом (инвариант: профиль нагрузки реален).
	byID := map[string]rules.Recognizer{}
	for _, r := range rules.Default() {
		byID[r.ID()] = r
	}
	const perGen = 300
	for gi, g := range gens {
		rng := newTestRNG(int64(gi + 1))
		r, ok := byID[g.id]
		if !ok {
			t.Fatalf("генератор ссылается на несуществующий recognizer %s", g.id)
		}
		for i := 0; i < perGen; i++ {
			if v := g.new(rng); !r.Match(v) {
				t.Fatalf("%s: сгенерированное значение %q не матчится", g.id, v)
			}
		}
	}
}

func TestRunDeterministic(t *testing.T) {
	recs := rules.Default()
	cfg := Config{Total: 20000, Seed: 42, ColSize: 1000, PosShare: 0.25}
	r1, err := Run(recs, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	r2, err := Run(recs, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r1.Generated.Positives != r2.Generated.Positives {
		t.Fatalf("детерминизм: positives %d != %d", r1.Generated.Positives, r2.Generated.Positives)
	}
	for i := range r1.Matches {
		if r1.Matches[i].Matched != r2.Matches[i].Matched {
			t.Fatalf("детерминизм: %s matched %d != %d", r1.Matches[i].RecognizerID, r1.Matches[i].Matched, r2.Matches[i].Matched)
		}
	}
}

func TestRunCountsAndNFRConsistency(t *testing.T) {
	recs := rules.Default()
	rep, err := Run(recs, Config{Total: 25000, Seed: 7, ColSize: 1000, PosShare: 0.3})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	g := rep.Generated
	if g.Positives+g.Negatives != g.Total || g.Total != 25000 {
		t.Fatalf("счётчики: positives+negatives=%d, total=%d", g.Positives+g.Negatives, g.Total)
	}
	if g.PosShare != 0.3 || g.Seed != 7 || g.ColSize != 1000 || g.Recognizers != len(recs) {
		t.Fatalf("параметры в отчёте не отражены: %+v", g)
	}
	if rep.ValuesPerMin != rep.ValuesPerSec*60 {
		t.Fatalf("values_per_min != values_per_sec*60: %f != %f", rep.ValuesPerMin, rep.ValuesPerSec*60)
	}
	if rep.NFRValuesPerMinPerCore != NFRThreshold {
		t.Fatalf("порог NFR: %f != %f", rep.NFRValuesPerMinPerCore, NFRThreshold)
	}
	if rep.NFRPass != (rep.ValuesPerMin >= NFRThreshold) {
		t.Fatalf("nfr_pass=%v не согласован с throughput %f", rep.NFRPass, rep.ValuesPerMin)
	}
	if len(rep.Matches) != len(recs) {
		t.Fatalf("matches: %d != %d recognizer'ов", len(rep.Matches), len(recs))
	}
}

func TestRunValidation(t *testing.T) {
	recs := rules.Default()
	base := Config{Total: 1000, Seed: 1, ColSize: 100, PosShare: 0.25}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"total<=0", func(c *Config) { c.Total = 0 }},
		{"col_size<=0", func(c *Config) { c.ColSize = 0 }},
		{"pos_share=0", func(c *Config) { c.PosShare = 0 }},
		{"pos_share=1", func(c *Config) { c.PosShare = 1 }},
	} {
		cfg := base
		tc.mut(&cfg)
		if _, err := Run(recs, cfg); err == nil {
			t.Errorf("%s: ожидалась ошибка валидации", tc.name)
		}
	}
	if _, err := Run(nil, base); err == nil {
		t.Error("пустой список recognizer'ов: ожидалась ошибка")
	}
}

func TestWriteReport(t *testing.T) {
	recs := rules.Default()
	rep, err := Run(recs, Config{Total: 5000, Seed: 3, ColSize: 1000, PosShare: 0.25})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(t.TempDir(), "reports", "bench.json")
	if err := WriteReport(path, rep); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение отчёта: %v", err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("отчёт не валиден как JSON: %v", err)
	}
	if back.Schema != rep.Schema || back.Generated.Total != rep.Generated.Total || !back.NFRPass {
		t.Fatalf("отчёт потерял поля: %+v", back)
	}
}
