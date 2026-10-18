// Package ensemble — сборка финального вердикта из кандидатов слоёв
// (blueprint п. 7). Этап 1: правило 1 (checksum → 0.99) и упрощённые правила
// 3/5 без LLM-слоя и эскалации; полная версия с взвешенным голосованием —
// этап 4 (agentproxy).
package ensemble

import (
	"math"

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
}

// Decide применяет правила blueprint п. 7 в объёме этапа 1:
//  1. кандидат слоя rules с checksum (0.99) → auto_accepted, конец пайплайна;
//  2. иначе лучший по confidence кандидат: ≥ tauAccept → auto_accepted
//     (слой ensemble, если кандидатов больше одного);
//  3. иначе → pending (очередь ручного ревью; серый коридор LLM — этап 4).
//
// Детерминизм: при равных confidence побеждает первый в порядке входа
// (engine подаёт кандидатов в фиксированном порядке: meta, rules).
func Decide(cands []Candidate, tauAccept float64) Outcome {
	if len(cands) == 0 {
		return Outcome{
			Label:        verdict.Label("UNKNOWN"),
			Confidence:   0,
			Layer:        verdict.LayerEnsemble,
			ReviewStatus: verdict.StatusPending,
		}
	}
	for _, c := range cands {
		if c.Layer == verdict.LayerRules && c.Confidence >= 0.99 {
			return Outcome{Label: c.Label, Confidence: 0.99, Layer: verdict.LayerRules, ReviewStatus: verdict.StatusAutoAccepted}
		}
	}
	best := cands[0]
	for _, c := range cands[1:] {
		if c.Confidence > best.Confidence {
			best = c
		}
	}
	if best.Confidence >= tauAccept {
		layer := best.Layer
		if len(cands) > 1 {
			layer = verdict.LayerEnsemble
		}
		return Outcome{Label: best.Label, Confidence: round4(best.Confidence), Layer: layer, ReviewStatus: verdict.StatusAutoAccepted}
	}
	return Outcome{Label: best.Label, Confidence: round4(best.Confidence), Layer: verdict.LayerEnsemble, ReviewStatus: verdict.StatusPending}
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }
