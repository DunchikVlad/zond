package scanengine

import (
	"fmt"
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// ResumeMismatch описывает одно отличие снимка конфигурации от прогона-чекпоинта.
type ResumeMismatch struct {
	Field   string `json:"field"`
	Stored  string `json:"stored"`
	Current string `json:"current"`
}

// ResumeCompatibilityError содержит все несовпадения provenance, а не только первое.
type ResumeCompatibilityError struct {
	Mismatches []ResumeMismatch
}

func (e *ResumeCompatibilityError) Error() string {
	parts := make([]string, 0, len(e.Mismatches))
	for _, m := range e.Mismatches {
		stored := m.Stored
		if stored == "" {
			stored = "не сохранено"
		}
		parts = append(parts, fmt.Sprintf("%s: было %q, стало %q", m.Field, stored, m.Current))
	}
	return "resume несовместим: " + strings.Join(parts, "; ")
}

// ValidateResume fail-closed сверяет provenance до продолжения прогона.
func ValidateResume(prev *store.Scan, cfg Config) error {
	current := []ResumeMismatch{
		{Field: "config_fingerprint", Stored: prev.ConfigFingerprint, Current: cfg.ConfigFingerprint},
		{Field: "taxonomy_version", Stored: prev.TaxonomyVersion, Current: cfg.TaxonomyVersion},
		{Field: "detectors_version", Stored: prev.DetectorsVersion, Current: cfg.DetectorsVersion},
		{Field: "binary_version", Stored: prev.BinaryVersion, Current: cfg.BinaryVersion},
	}
	mismatches := make([]ResumeMismatch, 0, len(current))
	for _, m := range current {
		if m.Stored != m.Current {
			mismatches = append(mismatches, m)
		}
	}
	if len(mismatches) > 0 {
		return &ResumeCompatibilityError{Mismatches: mismatches}
	}
	return nil
}
