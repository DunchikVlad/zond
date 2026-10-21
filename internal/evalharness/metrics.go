// Метрики и отчёт eval-harness'а: per-label P/R/F1, разрезы по видам
// колонок и спуфам, sweep tau_accept, экономика LLM (blueprint п. 16.6).
package evalharness

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/evalset"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// reportSchema — semver схемы отчёта: major — несовместимая смена полей,
// minor — добавление полей, patch — правки формулировок.
const reportSchema = "1.0.0"

// Report — машиночитаемый отчёт прогона (пишется в evals/reports/).
// Поля детерминированы: без wall-clock, порядок ключей JSON стабилен
// (карты сериализуются с сортировкой ключей encoding/json).
type Report struct {
	Schema  string                `json:"schema"`
	Dataset DatasetRef            `json:"dataset"`
	Config  ConfigRef             `json:"config"`
	Columns int                   `json:"columns"`
	Labels  map[string]*LabelStat `json:"labels"`
	Micro   AggStat               `json:"micro"`
	MacroF1 float64               `json:"macro_f1"`
	ByKind  map[string]*KindStat  `json:"by_kind"`
	Spoofs  map[string]*SpoofStat `json:"spoofs,omitempty"`
	Review  map[string]int        `json:"review_status"`
	Sweep   []SweepRow            `json:"sweep"`
	Econ    *Economics            `json:"economics,omitempty"`
}

// DatasetRef — происхождение выборки (манифест датасета).
type DatasetRef struct {
	Dir      string         `json:"dir"`
	Dataset  string         `json:"dataset"` // semver датасета
	Taxonomy string         `json:"taxonomy"`
	Seed     int64          `json:"seed"`
	Total    int            `json:"total"`
	Counts   evalset.Counts `json:"counts"`
}

// ConfigRef — конфигурация прогона (воспроизводимость отчёта).
type ConfigRef struct {
	TauAccept float64            `json:"tau_accept"`
	TauReview float64            `json:"tau_review"`
	Weights   map[string]float64 `json:"weights"`
	Band      [2]float64         `json:"band"`
	LLM       bool               `json:"llm"`
	AgentID   string             `json:"agent_id,omitempty"`
	Model     string             `json:"model,omitempty"`
	Prices    Prices             `json:"prices"`
}

// LabelStat — полная статистика одного лейбла (truth-разметка датасета).
type LabelStat struct {
	Support   int     `json:"support"`   // колонок с этим truth-лейблом
	Predicted int     `json:"predicted"` // колонок, отнесённых к лейблу
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// AggStat — микро-агрегат по всем лейблам.
type AggStat struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// KindStat — точность по виду колонок датасета (positive/spoof/…).
type KindStat struct {
	Total    int     `json:"total"`
	Correct  int     `json:"correct"` // предсказанный лейбл == truth
	Accuracy float64 `json:"accuracy"`
}

// SpoofStat — отдельная precision на спуфах (ADR-impl-6а D2): доля колонок
// UNKNOWN с spoofs=X, НЕ отнесённых к X (1.0 — чексумм-распознаватели и
// ансамбль не повелись ни на одну колонку-спуф).
type SpoofStat struct {
	Total          int     `json:"total"`
	Mispredicted   int     `json:"mispredicted_as_label"`
	SpoofPrecision float64 `json:"spoof_precision"`
}

// SweepRow — метрики при переоценке ансамбля с порогом tau_accept по
// кандидатам слоёв 0–1 (без LLM: детерминизм и нулевая стоимость перебора —
// ADR-impl-6б). F1All инвариантен к tau (лейбл всегда лучший кандидат),
// поэтому sweep показывает trade-off «доля автопринятых ↔ F1 на решённых».
type SweepRow struct {
	TauAccept    float64 `json:"tau_accept"`
	AutoAccepted int     `json:"auto_accepted"`
	Pending      int     `json:"pending"`
	F1All        float64 `json:"f1_all"`
	F1Decided    float64 `json:"f1_decided"` // micro-F1 только по auto_accepted
	MacroF1      float64 `json:"macro_f1"`
}

// Economics — учёт LLM-вызовов прогона и нормировка на 1000 колонок
// (blueprint п. 16.6 «токены и $ на 1000 колонок», п. 17).
type Economics struct {
	LLMCalls  int     `json:"llm_calls"`
	LLMErrors int     `json:"llm_errors"`
	TokensIn  int     `json:"tokens_in"`
	TokensOut int     `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	PricesSet bool    `json:"prices_set"` // false — цены не заданы, $ = 0
	Per1000   Per1000 `json:"per_1000_columns"`
}

// Per1000 — нормировка экономики на 1000 колонок.
type Per1000 struct {
	TokensIn  float64 `json:"tokens_in"`
	TokensOut float64 `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
}

// BuildReport собирает отчёт прогона: метрики по всем колонкам, разрезы,
// sweep и экономику. grid — сетка tau_accept для sweep (пустая — без sweep).
func BuildReport(m *evalset.Manifest, cols []evalset.Column, rr *RunResult, cfg Config, grid []float64, datasetDir, agentID, model string) *Report {
	rep := &Report{
		Schema: reportSchema,
		Dataset: DatasetRef{
			Dir: datasetDir, Dataset: m.Dataset, Taxonomy: m.Taxonomy,
			Seed: m.Seed, Total: len(cols), Counts: m.Counts,
		},
		Config: ConfigRef{
			TauAccept: cfg.TauAccept, TauReview: cfg.TauReview,
			Weights: weightsMap(cfg.Weights), Band: bandOf(cfg),
			LLM: cfg.LLM != nil, AgentID: agentID, Model: model,
			Prices: cfg.Prices,
		},
		Columns: len(cols),
		Labels:  labelStats(cols, rr.Outcomes, false),
		ByKind:  kindStats(cols, rr.Outcomes),
		Spoofs:  spoofStats(cols, rr.Outcomes),
		Review:  reviewStats(rr.Outcomes),
	}
	rep.Micro = microStats(rep.Labels)
	rep.MacroF1 = macroF1(rep.Labels)
	rep.Sweep = sweepRows(cols, rr.Outcomes, cfg, grid)
	if cfg.LLM != nil {
		rep.Econ = economics(rr, len(cols), cfg.Prices)
	}
	return rep
}

// labelStats — per-label статистика. decidedOnly=true — только колонки со
// статусом auto_accepted (метрики качества автопринятых решений для sweep).
func labelStats(cols []evalset.Column, outs []ColumnOutcome, decidedOnly bool) map[string]*LabelStat {
	stats := map[string]*LabelStat{}
	consider := func(i int) (verdict.Label, verdict.Label, bool) {
		if i >= len(outs) {
			return "", "", false
		}
		if decidedOnly && outs[i].ReviewStatus != verdict.StatusAutoAccepted {
			return "", "", false
		}
		return cols[i].Label, outs[i].Label, true
	}
	for i := range cols {
		truth, pred, ok := consider(i)
		if !ok {
			continue
		}
		s := stats[string(truth)]
		if s == nil {
			s = &LabelStat{}
			stats[string(truth)] = s
		}
		s.Support++
		p := stats[string(pred)]
		if p == nil {
			p = &LabelStat{}
			stats[string(pred)] = p
		}
		p.Predicted++
		if pred == truth {
			s.TP++
		} else {
			p.FP++
			s.FN++
		}
	}
	for _, s := range stats {
		s.Precision = prf(float64(s.TP), float64(s.TP+s.FP))
		s.Recall = prf(float64(s.TP), float64(s.TP+s.FN))
		s.F1 = prf(2*s.Precision*s.Recall, s.Precision+s.Recall)
	}
	return stats
}

// microStats — микро-агрегат: суммы TP/FP/FN по лейблам.
func microStats(stats map[string]*LabelStat) AggStat {
	var tp, fp, fn int
	for _, s := range stats {
		tp += s.TP
		fp += s.FP
		fn += s.FN
	}
	p := prf(float64(tp), float64(tp+fp))
	r := prf(float64(tp), float64(tp+fn))
	return AggStat{Precision: p, Recall: r, F1: prf(2*p*r, p+r)}
}

// macroF1 — среднее F1 по лейблам с ненулевой поддержкой или предсказаниями.
func macroF1(stats map[string]*LabelStat) float64 {
	var sum float64
	var n int
	for _, s := range stats {
		if s.Support == 0 && s.Predicted == 0 {
			continue
		}
		sum += s.F1
		n++
	}
	return prf(sum, float64(n))
}

// kindStats — точность по виду колонок (truth сверяется с предсказанным
// лейблом; для спуфов «верно» = UNKNOWN, п. 16.6).
func kindStats(cols []evalset.Column, outs []ColumnOutcome) map[string]*KindStat {
	stats := map[string]*KindStat{}
	for i := range cols {
		ks := stats[string(cols[i].Kind)]
		if ks == nil {
			ks = &KindStat{}
			stats[string(cols[i].Kind)] = ks
		}
		ks.Total++
		if i < len(outs) && outs[i].Label == cols[i].Label {
			ks.Correct++
		}
	}
	for _, ks := range stats {
		ks.Accuracy = prf(float64(ks.Correct), float64(ks.Total))
	}
	return stats
}

// spoofStats — precision на спуфах по имитируемым лейблам (ADR-impl-6а D2).
func spoofStats(cols []evalset.Column, outs []ColumnOutcome) map[string]*SpoofStat {
	stats := map[string]*SpoofStat{}
	for i := range cols {
		if cols[i].Kind != evalset.KindSpoof {
			continue
		}
		target := cols[i].Spoofs
		if target == "" {
			continue
		}
		ss := stats[target]
		if ss == nil {
			ss = &SpoofStat{}
			stats[target] = ss
		}
		ss.Total++
		if i < len(outs) && string(outs[i].Label) == target {
			ss.Mispredicted++
		}
	}
	for _, ss := range stats {
		ss.SpoofPrecision = prf(float64(ss.Total-ss.Mispredicted), float64(ss.Total))
	}
	return stats
}

// reviewStats — счётчик статусов ревью прогона.
func reviewStats(outs []ColumnOutcome) map[string]int {
	stats := map[string]int{}
	for _, o := range outs {
		stats[string(o.ReviewStatus)]++
	}
	return stats
}

// sweepRows — перебор tau_accept: ансамбль переоценивается по кандидатам
// слоёв 0–1 каждой колонки (LLM не участвует — детерминизм; ADR-impl-6б).
func sweepRows(cols []evalset.Column, outs []ColumnOutcome, cfg Config, grid []float64) []SweepRow {
	band := bandOf(cfg)
	rows := make([]SweepRow, 0, len(grid))
	for _, tau := range grid {
		row := SweepRow{TauAccept: tau}
		simOuts := make([]ColumnOutcome, 0, len(cols))
		for i := range cols {
			var o ensemble.Outcome
			if i < len(outs) && len(outs[i].Candidates) > 0 {
				o = ensemble.Decide(outs[i].Candidates, tau, cfg.Weights, band)
			} else {
				o = ensemble.Outcome{Label: verdict.Label("UNKNOWN"), Layer: verdict.LayerEnsemble, ReviewStatus: verdict.StatusPending}
			}
			if o.ReviewStatus == verdict.StatusAutoAccepted {
				row.AutoAccepted++
			} else {
				row.Pending++
			}
			sim := outs[i]
			sim.Label = o.Label
			sim.ReviewStatus = o.ReviewStatus
			simOuts = append(simOuts, sim)
		}
		row.F1All = microStats(labelStats(cols, simOuts, false)).F1
		row.F1Decided = microStats(labelStats(cols, simOuts, true)).F1
		row.MacroF1 = macroF1(labelStats(cols, simOuts, false))
		rows = append(rows, row)
	}
	return rows
}

// economics — экономика прогона с нормировкой на 1000 колонок (п. 16.6).
func economics(rr *RunResult, columns int, p Prices) *Economics {
	per := func(v float64) float64 {
		if columns == 0 {
			return 0
		}
		return round4(v / float64(columns) * 1000)
	}
	return &Economics{
		LLMCalls: rr.LLMCalls, LLMErrors: rr.LLMErrors,
		TokensIn: rr.TokensIn, TokensOut: rr.TokensOut,
		CostUSD:   round6(rr.CostUSD),
		PricesSet: p.In > 0 || p.Out > 0,
		Per1000: Per1000{
			TokensIn:  per(float64(rr.TokensIn)),
			TokensOut: per(float64(rr.TokensOut)),
			CostUSD:   per(rr.CostUSD),
		},
	}
}

// Text — человекочитаемая сводка отчёта (консоль cmd/eval).
func (r *Report) Text(w io.Writer) {
	fmt.Fprintf(w, "\n=== Eval-отчёт: датасет %s (taxonomy %s, seed %d, %d колонок) ===\n",
		r.Dataset.Dataset, r.Dataset.Taxonomy, r.Dataset.Seed, r.Columns)
	fmt.Fprintf(w, "Конфиг: tau_accept=%g tau_review=%g band=[%g %g] веса=%v LLM: %s\n",
		r.Config.TauAccept, r.Config.TauReview, r.Config.Band[0], r.Config.Band[1],
		r.Config.Weights, onOff(r.Config.LLM))
	fmt.Fprintln(w, "Метрики по лейблам (support / predicted / P / R / F1):")
	for _, l := range sortedKeys(r.Labels) {
		s := r.Labels[l]
		fmt.Fprintf(w, "  %-16s %4d / %4d  P=%.3f R=%.3f F1=%.3f\n",
			l, s.Support, s.Predicted, s.Precision, s.Recall, s.F1)
	}
	fmt.Fprintf(w, "micro: P=%.3f R=%.3f F1=%.3f; macro F1=%.3f\n",
		r.Micro.Precision, r.Micro.Recall, r.Micro.F1, r.MacroF1)
	fmt.Fprintln(w, "По видам колонок:")
	for _, k := range sortedKeys(r.ByKind) {
		ks := r.ByKind[k]
		fmt.Fprintf(w, "  %-12s %4d колонок, точность %.3f (%d верно)\n", k, ks.Total, ks.Accuracy, ks.Correct)
	}
	if len(r.Spoofs) > 0 {
		fmt.Fprintln(w, "Spoof-precision (доля спуфов, НЕ отнесённых к имитируемому лейблу):")
		for _, l := range sortedKeys(r.Spoofs) {
			ss := r.Spoofs[l]
			fmt.Fprintf(w, "  %-14s %.3f (%d/%d повелись)\n", l, ss.SpoofPrecision, ss.Mispredicted, ss.Total)
		}
	}
	fmt.Fprintf(w, "Статусы ревью: %v\n", r.Review)
	if len(r.Sweep) > 0 {
		fmt.Fprintln(w, "Sweep tau_accept (переоценка слоёв 0+1 без LLM):")
		fmt.Fprintln(w, "  tau    auto  pending  F1(all)  F1(decided)  macroF1")
		for _, s := range r.Sweep {
			fmt.Fprintf(w, "  %.2f  %4d  %6d  %.3f      %.3f        %.3f\n",
				s.TauAccept, s.AutoAccepted, s.Pending, s.F1All, s.F1Decided, s.MacroF1)
		}
	}
	if r.Econ != nil {
		fmt.Fprintf(w, "Экономика LLM: вызовов %d (ошибок %d), токены in/out %d/%d, $%.6f\n",
			r.Econ.LLMCalls, r.Econ.LLMErrors, r.Econ.TokensIn, r.Econ.TokensOut, r.Econ.CostUSD)
		fmt.Fprintf(w, "На 1000 колонок: токены %.0f/%.0f, $%.4f (цены заданы: %v)\n",
			r.Econ.Per1000.TokensIn, r.Econ.Per1000.TokensOut, r.Econ.Per1000.CostUSD, r.Econ.PricesSet)
	}
}

// WriteReport пишет отчёт в path (mkdir -p, indent, LF) — артефакт
// фиксируется в репозитории (evals/reports/, blueprint п. 16.6).
func WriteReport(path string, r *Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("evalharness: каталог %s: %w", filepath.Dir(path), err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("evalharness: отчёт: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("evalharness: %s: %w", path, err)
	}
	return nil
}

// prf — частное с нулевым знаменателем → 0 (округление до 4 знаков).
func prf(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	return round4(num / den)
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
func round6(f float64) float64 { return math.Round(f*1e6) / 1e6 }

func weightsMap(w ensemble.Weights) map[string]float64 {
	if len(w) == 0 {
		return map[string]float64{}
	}
	out := make(map[string]float64, len(w))
	for k, v := range w {
		out[string(k)] = v
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
