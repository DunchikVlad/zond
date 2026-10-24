// Package benchlab — нагрузочный тест слоя 1 (blueprint п. 16.8):
// детерминированный поток синтетических значений (позитивы всех
// recognizer'ов + негативы) через rules.Analyze по «колонкам» — зеркало
// пути scanengine (engine.go); замер пропускной способности и сверка
// с NFR п. 18 (≥100 000 значений/мин на 1 ядро).
package benchlab

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// Config — параметры прогона.
type Config struct {
	Total     int     // всего значений (п. 16.8: 1 000 000)
	Seed      int64   // seed детерминированной генерации (math/rand/v2 PCG)
	ColSize   int     // значений в «колонке» — один вызов rules.Analyze
	PosShare  float64 // доля позитивов (0..1), остальное — негативы
	Threshold float64 // порог NFR, значений/мин на ядро (0 — NFRThreshold)
}

// RecogStat — агрегат матчей recognizer'я за прогон.
type RecogStat struct {
	RecognizerID string        `json:"recognizer"`
	Label        verdict.Label `json:"label"`
	HasChecksum  bool          `json:"has_checksum"`
	Matched      int           `json:"matched"`
}

// Generated — что реально сгенерировано (фактические счётчики, не план).
type Generated struct {
	Total       int     `json:"total"`
	Positives   int     `json:"positives"`
	Negatives   int     `json:"negatives"`
	Seed        int64   `json:"seed"`
	ColSize     int     `json:"col_size"`
	PosShare    float64 `json:"pos_share"`
	Recognizers int     `json:"recognizers"`
}

// Report — машиночитаемый отчёт прогона (пишется в evals/reports/).
// Содержит wall-clock метрики — в git не коммитится (см. .gitignore).
type Report struct {
	Schema                 string      `json:"schema"`
	Generated              Generated   `json:"generated"`
	Matches                []RecogStat `json:"matches"`
	DurationMS             float64     `json:"duration_ms"`
	ValuesPerSec           float64     `json:"values_per_sec"`
	ValuesPerMin           float64     `json:"values_per_min"`
	NFRValuesPerMinPerCore float64     `json:"nfr_values_per_min_per_core"`
	NFRPass                bool        `json:"nfr_pass"`
}

// NFRThreshold — требование п. 18: значений/мин на 1 CPU-ядро.
const NFRThreshold = 100_000.0

// Run — генерация значений и прогон recognizer'ов слоя 1 с замером.
// Генерация выполняется до старта таймера; классификация — одной
// горутиной (пропускная способность на ядро).
func Run(recs []rules.Recognizer, cfg Config) (*Report, error) {
	if cfg.Total <= 0 {
		return nil, errors.New("benchlab: total должен быть > 0")
	}
	if cfg.ColSize <= 0 {
		return nil, errors.New("benchlab: col_size должен быть > 0")
	}
	if cfg.PosShare <= 0 || cfg.PosShare >= 1 {
		return nil, fmt.Errorf("benchlab: pos_share должен быть в (0, 1), получено %v", cfg.PosShare)
	}
	if len(recs) == 0 {
		return nil, errors.New("benchlab: список recognizer'ов пуст")
	}
	threshold := cfg.Threshold
	if threshold == 0 {
		threshold = NFRThreshold
	}
	if threshold < 0 {
		return nil, fmt.Errorf("benchlab: порог NFR должен быть >= 0, получено %v", cfg.Threshold)
	}

	rng := rand.New(rand.NewPCG(uint64(cfg.Seed), uint64(cfg.Seed>>1)|1))
	values, positives := generate(rng, cfg)

	start := time.Now()
	stats := make(map[string]*RecogStat, len(recs))
	for _, r := range recs {
		stats[r.ID()] = &RecogStat{RecognizerID: r.ID(), Label: r.Label(), HasChecksum: r.HasChecksum()}
	}
	for col := 0; col < len(values); col += cfg.ColSize {
		end := min(col+cfg.ColSize, len(values))
		for _, m := range rules.Analyze(values[col:end], recs...) {
			stats[m.RecognizerID].Matched += m.Matched
		}
	}
	dur := time.Since(start)

	matches := make([]RecogStat, 0, len(recs))
	for _, r := range recs {
		matches = append(matches, *stats[r.ID()])
	}
	perSec := float64(len(values)) / dur.Seconds()
	rep := &Report{
		Schema: "zond/bench-report@1",
		Generated: Generated{
			Total: len(values), Positives: positives, Negatives: len(values) - positives,
			Seed: cfg.Seed, ColSize: cfg.ColSize, PosShare: cfg.PosShare, Recognizers: len(recs),
		},
		Matches:                matches,
		DurationMS:             float64(dur.Microseconds()) / 1000.0,
		ValuesPerSec:           perSec,
		ValuesPerMin:           perSec * 60,
		NFRValuesPerMinPerCore: threshold,
		NFRPass:                perSec*60 >= threshold,
	}
	return rep, nil
}

// generate — детерминированный поток значений: PosShare — позитивы
// (категория выбирается равновероятно по gens), остальное — негативы
// (шаблон выбирается равновероятно по negatives).
func generate(rng *rand.Rand, cfg Config) ([]string, int) {
	values := make([]string, cfg.Total)
	positives := 0
	for i := range values {
		if rng.Float64() < cfg.PosShare {
			values[i] = gens[rng.IntN(len(gens))].new(rng)
			positives++
		} else {
			values[i] = negatives[rng.IntN(len(negatives))](rng)
		}
	}
	return values, positives
}

// WriteReport — запись JSON-отчёта (mkdir -p по пути, LF).
func WriteReport(path string, r *Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("benchlab: маршалинг отчёта: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("benchlab: каталог отчёта: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("benchlab: запись отчёта: %w", err)
	}
	return nil
}
