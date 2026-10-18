package ensemble

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/verdict"
)

func TestChecksumWins(t *testing.T) {
	out := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "CARD_NUMBER", Confidence: 0.99, Layer: verdict.LayerRules},
	}, 0.80)
	if out.Label != "CARD_NUMBER" || out.Layer != verdict.LayerRules || out.ReviewStatus != verdict.StatusAutoAccepted {
		t.Fatalf("правило 1 не сработало: %+v", out)
	}
}

func TestAutoAcceptAboveTau(t *testing.T) {
	out := Decide([]Candidate{
		{Label: "PHONE", Confidence: 0.90, Layer: verdict.LayerRules},
	}, 0.80)
	if out.Label != "PHONE" || out.ReviewStatus != verdict.StatusAutoAccepted || out.Layer != verdict.LayerRules {
		t.Fatalf("auto_accepted не выставлен: %+v", out)
	}
}

func TestBelowTauPending(t *testing.T) {
	out := Decide([]Candidate{
		{Label: "PHONE", Confidence: 0.70, Layer: verdict.LayerRules},
	}, 0.80)
	if out.ReviewStatus != verdict.StatusPending || out.Layer != verdict.LayerEnsemble {
		t.Fatalf("ожидался pending: %+v", out)
	}
}

func TestMultipleCandidatesMarkEnsemble(t *testing.T) {
	out := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "EMAIL", Confidence: 0.90, Layer: verdict.LayerRules},
	}, 0.80)
	if out.Layer != verdict.LayerEnsemble || out.Confidence != 0.90 {
		t.Fatalf("слой ensemble не проставлен: %+v", out)
	}
}

func TestNoCandidatesUnknown(t *testing.T) {
	out := Decide(nil, 0.80)
	if out.Label != "UNKNOWN" || out.ReviewStatus != verdict.StatusPending {
		t.Fatalf("UNKNOWN/pending ожидался: %+v", out)
	}
}

func TestDeterministicTie(t *testing.T) {
	a := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "PHONE", Confidence: 0.85, Layer: verdict.LayerMeta},
	}, 0.80)
	b := Decide([]Candidate{
		{Label: "EMAIL", Confidence: 0.85, Layer: verdict.LayerMeta},
		{Label: "PHONE", Confidence: 0.85, Layer: verdict.LayerMeta},
	}, 0.80)
	if a != b {
		t.Fatalf("недетерминизм: %+v vs %+v", a, b)
	}
}
