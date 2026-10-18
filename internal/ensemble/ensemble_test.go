package ensemble

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/verdict"
)

var (
	testWeights = Weights{verdict.LayerMeta: 1.0, verdict.LayerRules: 1.5, verdict.LayerLLM: 1.2}
	grayBand    = [2]float64{0.30, 0.70}
)

func TestChecksumWins(t *testing.T) {
	out := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "CARD_NUMBER", Confidence: 0.99, Layer: verdict.LayerRules},
	}, 0.80, testWeights, grayBand)
	if out.Label != "CARD_NUMBER" || out.Layer != verdict.LayerRules || out.ReviewStatus != verdict.StatusAutoAccepted {
		t.Fatalf("правило 1 не сработало: %+v", out)
	}
}

func TestAutoAcceptAboveTauWithMargin(t *testing.T) {
	// один сильный кандидат ≥ tau, отрыва нет (нет второго) → auto_accepted
	out := Decide([]Candidate{
		{Label: "PHONE", Confidence: 0.90, Layer: verdict.LayerRules},
	}, 0.80, testWeights, grayBand)
	if out.Label != "PHONE" || out.ReviewStatus != verdict.StatusAutoAccepted {
		t.Fatalf("auto_accepted не выставлен: %+v", out)
	}
}

func TestWeightedVoting(t *testing.T) {
	// meta(0.85·1.0) vs rules(0.70·1.5): score EMAIL=0.85, PHONE=1.05 → PHONE
	out := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "PHONE", Confidence: 0.70, Layer: verdict.LayerRules},
	}, 0.80, testWeights, grayBand)
	if out.Label != "PHONE" {
		t.Fatalf("взвешенное голосование: %+v", out)
	}
}

func TestGrayZoneEscalate(t *testing.T) {
	// best.conf в серой зоне [0.3,0.7] → сигнал эскалации
	out := Decide([]Candidate{
		{Label: "PHONE", Confidence: 0.50, Layer: verdict.LayerLLM},
		{Label: "EMAIL", Confidence: 0.40, Layer: verdict.LayerMeta},
	}, 0.80, testWeights, grayBand)
	if !out.Escalate || out.GrayBest.Label != "PHONE" || out.ReviewStatus != verdict.StatusPending {
		t.Fatalf("ожидалась эскалация в серой зоне: %+v", out)
	}
}

func TestBelowGrayPending(t *testing.T) {
	// ниже серой зоны → pending без эскалации
	out := Decide([]Candidate{
		{Label: "FREE_TEXT", Confidence: 0.20, Layer: verdict.LayerMeta},
	}, 0.80, testWeights, grayBand)
	if out.Escalate || out.ReviewStatus != verdict.StatusPending {
		t.Fatalf("ожидался pending без эскалации: %+v", out)
	}
}

func TestNoCandidatesUnknown(t *testing.T) {
	out := Decide(nil, 0.80, testWeights, grayBand)
	if out.Label != "UNKNOWN" || out.ReviewStatus != verdict.StatusPending {
		t.Fatalf("UNKNOWN/pending ожидался: %+v", out)
	}
}

func TestDeterministicTieLexicographic(t *testing.T) {
	// равные score → лексикографически меньший лейбл
	a := Decide([]Candidate{
		{Label: "PHONE", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
	}, 0.80, testWeights, grayBand)
	b := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "PHONE", Confidence: 0.85, Layer: verdict.LayerMeta},
	}, 0.80, testWeights, grayBand)
	if a != b || a.Label != "EMAIL" {
		t.Fatalf("tie-break не лексикографический/недетерминизм: %+v vs %+v", a, b)
	}
}

func TestApplyVerifierConfirm(t *testing.T) {
	gray := Outcome{Label: "PHONE", Confidence: 0.60, Layer: verdict.LayerEnsemble, ReviewStatus: verdict.StatusPending, Escalate: true}
	out := ApplyVerifier(gray, VerifierOutcome{Verdict: "confirm", Label: "PHONE", Confidence: 0.85}, 0.80)
	if out.Label != "PHONE" || out.Confidence != 0.70 || out.ReviewStatus != verdict.StatusAutoAccepted || out.Layer != verdict.LayerLLM {
		t.Fatalf("confirm не применён (+0.1): %+v", out)
	}
}

func TestApplyVerifierConfirmCap(t *testing.T) {
	gray := Outcome{Label: "PHONE", Confidence: 0.90, ReviewStatus: verdict.StatusPending, Escalate: true}
	out := ApplyVerifier(gray, VerifierOutcome{Verdict: "confirm", Label: "PHONE", Confidence: 0.95}, 0.80)
	if out.Confidence != 0.95 {
		t.Fatalf("cap 0.95 не применён: %+v", out)
	}
}

func TestApplyVerifierReject(t *testing.T) {
	gray := Outcome{Label: "PHONE", Confidence: 0.60, ReviewStatus: verdict.StatusPending, Escalate: true}
	out := ApplyVerifier(gray, VerifierOutcome{Verdict: "reject", Label: "FREE_TEXT", Confidence: 0.55}, 0.80)
	if out.Label != "FREE_TEXT" || out.ReviewStatus != verdict.StatusPending {
		t.Fatalf("reject не применён: %+v", out)
	}
}

func TestApplyVerifierRejectAboveTau(t *testing.T) {
	gray := Outcome{Label: "PHONE", Confidence: 0.60, ReviewStatus: verdict.StatusPending, Escalate: true}
	out := ApplyVerifier(gray, VerifierOutcome{Verdict: "reject", Label: "EMAIL", Confidence: 0.90}, 0.80)
	if out.Label != "EMAIL" || out.ReviewStatus != verdict.StatusAutoAccepted {
		t.Fatalf("reject ≥ tau должен auto_accepted: %+v", out)
	}
}
