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

// LLMStatus — состояние LLM-обработки колонки (S9-2, blueprint S9 п. 3):
// фиксирует, что именно произошло на слое 2 каскада — вызов, попадание в кэш,
// отказ по бюджету/сэмплу, распространение от представителя кластера или
// ошибка агента. Пустая строка (строки до миграции 0011) трактуется как
// «неизвестно» и не отфильтровывается ни одним статусом.
type LLMStatus string

const (
	LLMStatusNotCalled         LLMStatus = "not_called"
	LLMStatusCalled            LLMStatus = "called"
	LLMStatusCacheHit          LLMStatus = "cache_hit"
	LLMStatusSmallSample       LLMStatus = "small_sample"
	LLMStatusClusterPropagated LLMStatus = "cluster_propagated"
	LLMStatusBudgetExceeded    LLMStatus = "budget_exceeded"
	LLMStatusError             LLMStatus = "error"
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
	LLMStatus        LLMStatus // S9-2: состояние LLM-обработки колонки
	ReviewStatus     ReviewStatus
	FinalLabel       Label
	ReviewedBy       string
	ReviewedAt       time.Time
	CreatedAt        time.Time
}
