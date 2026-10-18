// Package verdict — доменная модель вердикта классификации.
// Контракт: blueprint.md п. 5.4, п. 5.5; ADR-0004 (таксономия как код).
package verdict

import "time"

// Sensitivity — класс чувствительности данных (blueprint п. 5.5).
type Sensitivity string

const (
	SensitivityPII  Sensitivity = "PII"
	SensitivityPCI  Sensitivity = "PCI"
	SensitivityPHI  Sensitivity = "PHI"
	SensitivityNone Sensitivity = "none"
)

// Label — лейбл таксономии. Полный набор версионируется в configs/taxonomy.yaml;
// сгенерированные константы лейблов — на этапе go generate (ADR-0004).
type Label string

// EvidenceLayer — слой каскада, принявший решение (blueprint п. 7).
type EvidenceLayer string

const (
	LayerMeta     EvidenceLayer = "meta"
	LayerRules    EvidenceLayer = "rules"
	LayerLLM      EvidenceLayer = "llm"
	LayerEnsemble EvidenceLayer = "ensemble"
)

// ReviewStatus — статус ревью вердикта (blueprint п. 5.4).
type ReviewStatus string

const (
	StatusAutoAccepted ReviewStatus = "auto_accepted"
	StatusPending      ReviewStatus = "pending"
	StatusConfirmed    ReviewStatus = "confirmed"
	StatusRejected     ReviewStatus = "rejected"
	StatusRelabelled   ReviewStatus = "relabelled"
)

// Verdict — атомарный результат классификации одной колонки/пути
// (blueprint п. 5.4). Evidence содержит только маскированные примеры (ADR-0010).
type Verdict struct {
	ID               string
	ScanID           string
	Table            string
	Path             string
	NativeType       string
	Label            Label
	Sensitivity      Sensitivity
	Confidence       float64
	EvidenceLayer    EvidenceLayer
	Evidence         map[string]any
	TaxonomyVersion  string
	DetectorsVersion string
	PromptVersion    string
	SampleSize       int
	ClusterID        string
	ReviewStatus     ReviewStatus
	FinalLabel       Label
	ReviewedBy       string
	ReviewedAt       time.Time
	CreatedAt        time.Time
}
