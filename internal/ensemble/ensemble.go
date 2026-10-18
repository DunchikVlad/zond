// Package ensemble — сборка финального вердикта из кандидатов слоёв
// (blueprint п. 7). Полная версия этапа 4: правило 1 (checksum → 0.99),
// взвешенное голосование (правило 2), порог+отрыв (правило 3), эскалация в
// режиме верификатора (правило 4), иначе pending (правило 5). Детерминизм:
// один вход — один вердикт; tie-break лексикографический; округление до 4 знаков.
package ensemble

import (
	"math"
	"sort"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// Candidate — лейбл с confidence от одного слоя.
type Candidate struct {
	Label      verdict.Label
	Confidence float64
	Layer      verdict.EvidenceLayer
}

// Outcome — решение ансамбля для одной колонки.
type Outcome struct {
	Label        verdict.Label
	Confidence   float64
	Layer        verdict.EvidenceLayer
	ReviewStatus verdict.ReviewStatus
	// Escalate — сигнал движку вызвать верификатора (правило 4): best.score в
	// серой зоне и настроен escalate_to. Движок после верификатора вызывает
	// ApplyVerifier.
	Escalate bool
	// GrayBest — лучший кандидат для верификатора (кандидатный лейбл).
	GrayBest Candidate
}

// Weights — веса слоёв для взвешенного голосования (config ensemble.weights).
type Weights map[verdict.EvidenceLayer]float64

// DefaultWeights — веса по умолчанию (blueprint п. 7: meta 1.0, rules 1.5, llm 1.2).
var DefaultWeights = Weights{
	verdict.LayerMeta:  1.0,
	verdict.LayerRules: 1.5,
	verdict.LayerLLM:   1.2,
}

// VerifierOutcome — результат вызова верификатора (п. 5.3).
type VerifierOutcome struct {
	Verdict    string // confirm | reject
	Label      verdict.Label
	Confidence float64
}

// Decide применяет правила blueprint п. 7:
//  1. кандидат слоя rules с checksum (0.99) → auto_accepted, конец пайплайна;
//  2. иначе взвешенное голосование: score[l] = Σ(w·c); confidence = Σ(w·c)/Σw;
//  3. best.score ≥ tauAccept и отрыв от второго ≥ 0.3 → auto_accepted;
//  4. иначе best.score в серой зоне [bandLo, bandHi] и escalate — сигнал Escalate;
//  5. иначе → pending.
//
// Детерминизм: tie-break при равных score — лексикографически меньший лейбл;
// округление до 4 знаков одинаково для всех слоёв.
func Decide(cands []Candidate, tauAccept float64, w Weights, band [2]float64) Outcome {
	if len(cands) == 0 {
		return Outcome{
			Label:        verdict.Label("UNKNOWN"),
			Confidence:   0,
			Layer:        verdict.LayerEnsemble,
			ReviewStatus: verdict.StatusPending,
		}
	}
	// правило 1: checksum слоя rules → 0.99, конец
	for _, c := range cands {
		if c.Layer == verdict.LayerRules && c.Confidence >= 0.99 {
			return Outcome{Label: c.Label, Confidence: 0.99, Layer: verdict.LayerRules, ReviewStatus: verdict.StatusAutoAccepted}
		}
	}
	// правило 2: взвешенное голосование
	if len(w) == 0 {
		w = DefaultWeights
	}
	type agg struct {
		sumWC float64
		sumW  float64
	}
	byLabel := map[verdict.Label]*agg{}
	for _, c := range cands {
		wgt := w[c.Layer]
		if wgt <= 0 {
			wgt = 1.0
		}
		a := byLabel[c.Label]
		if a == nil {
			a = &agg{}
			byLabel[c.Label] = a
		}
		a.sumWC += wgt * c.Confidence
		a.sumW += wgt
	}
	type scored struct {
		label verdict.Label
		score float64
		conf  float64 // Σ(w·c)/Σw
	}
	scores := make([]scored, 0, len(byLabel))
	for l, a := range byLabel {
		conf := 0.0
		if a.sumW > 0 {
			conf = a.sumWC / a.sumW
		}
		scores = append(scores, scored{label: l, score: a.sumWC, conf: conf})
	}
	// детерминизм: по убыванию score, при равенстве — лексикографически меньший лейбл
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score != scores[j].score {
			return scores[i].score > scores[j].score
		}
		return scores[i].label < scores[j].label
	})
	best := scores[0]
	var second float64
	if len(scores) > 1 {
		second = scores[1].score
	}
	// правило 3: порог + отрыв ≥ 0.3 → auto_accepted
	if best.conf >= tauAccept && best.score-second >= 0.3 {
		return Outcome{Label: best.label, Confidence: round4(best.conf), Layer: verdict.LayerEnsemble, ReviewStatus: verdict.StatusAutoAccepted}
	}
	// правило 4: серая зона → эскалация в верификатор
	if best.conf >= band[0] && best.conf <= band[1] {
		return Outcome{
			Label:        best.label,
			Confidence:   round4(best.conf),
			Layer:        verdict.LayerEnsemble,
			ReviewStatus: verdict.StatusPending,
			Escalate:     true,
			GrayBest:     Candidate{Label: best.label, Confidence: best.conf, Layer: verdict.LayerEnsemble},
		}
	}
	// правило 5: pending
	return Outcome{Label: best.label, Confidence: round4(best.conf), Layer: verdict.LayerEnsemble, ReviewStatus: verdict.StatusPending}
}

// ApplyVerifier применяет результат верификатора к решению из серой зоны
// (blueprint п. 7 правило 4): confirm → confidence+0.1, cap 0.95, auto_accepted;
// reject → лейбл верификатора с его confidence, далее пересчёт по порогам.
func ApplyVerifier(gray Outcome, vo VerifierOutcome, tauAccept float64) Outcome {
	if vo.Verdict == "confirm" {
		conf := math.Min(gray.Confidence+0.1, 0.95)
		return Outcome{
			Label:        vo.Label,
			Confidence:   round4(conf),
			Layer:        verdict.LayerLLM,
			ReviewStatus: verdict.StatusAutoAccepted,
		}
	}
	// reject: лейбл верификатора; auto_accepted только если ≥ tauAccept
	status := verdict.StatusPending
	if vo.Confidence >= tauAccept {
		status = verdict.StatusAutoAccepted
	}
	return Outcome{
		Label:        vo.Label,
		Confidence:   round4(vo.Confidence),
		Layer:        verdict.LayerLLM,
		ReviewStatus: status,
	}
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
