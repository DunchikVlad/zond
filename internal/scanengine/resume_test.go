package scanengine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

func TestValidateResume(t *testing.T) {
	cfg := Config{ConfigFingerprint: "cfg", TaxonomyVersion: "tax", DetectorsVersion: "det", BinaryVersion: "bin"}
	prev := &store.Scan{ConfigFingerprint: "cfg", TaxonomyVersion: "tax", DetectorsVersion: "det", BinaryVersion: "bin"}
	if err := ValidateResume(prev, cfg); err != nil {
		t.Fatalf("совместимый resume: %v", err)
	}
	prev.TaxonomyVersion = "old"
	prev.BinaryVersion = ""
	err := ValidateResume(prev, cfg)
	var compat *ResumeCompatibilityError
	if !errors.As(err, &compat) {
		t.Fatalf("ожидался ResumeCompatibilityError: %v", err)
	}
	if len(compat.Mismatches) != 2 || compat.Mismatches[0].Field != "taxonomy_version" || compat.Mismatches[1].Field != "binary_version" {
		t.Fatalf("не все различия перечислены: %+v", compat.Mismatches)
	}
}

func TestEngineRejectsIncompatibleResumeBeforeNewScan(t *testing.T) {
	eng, st := testEngine(t)
	eng.cfg.ConfigFingerprint = "current"
	eng.cfg.BinaryVersion = "current"
	prev := &store.Scan{
		ID: "legacy", SourceName: "fake", Profile: "deep", Status: "partial", StartedAt: time.Now().UTC(),
		ConfigFingerprint: "old", TaxonomyVersion: eng.cfg.TaxonomyVersion,
		DetectorsVersion: eng.cfg.DetectorsVersion, BinaryVersion: "old",
	}
	if err := st.SaveScan(context.Background(), prev); err != nil {
		t.Fatal(err)
	}
	eng.cfg.ResumeFrom = prev.ID
	_, err := eng.Scan(context.Background(), testSource(), "fake", "deep")
	var compat *ResumeCompatibilityError
	if !errors.As(err, &compat) || len(compat.Mismatches) != 2 {
		t.Fatalf("ожидались два mismatch: %v", err)
	}
	_, total, listErr := st.ListScans(context.Background(), store.ScanFilter{})
	if listErr != nil || total != 1 {
		t.Fatalf("после отказа создан новый прогон: total=%d err=%v", total, listErr)
	}
}
