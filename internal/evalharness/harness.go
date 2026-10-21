// Package evalharness — eval-harness этапа 6 (blueprint п. 16.6): прогон
// каскада классификации (слои 0–2 + ансамбль, п. 7) по эталонному датасету
// evalset, метрики precision/recall/F1 по лейблам, sweep порога tau_accept,
// отчёт «токены и $ на 1000 колонок». Контур самостоятельный: без store,
// аудита и коннекторов (ADR-impl-6а D1) — порядок слоёв и правила ансамбля
// дублируют scanengine.verdict за вычетом кэша, кластеризации и budget-стопа
// (риск дивергенции зафиксирован в ADR-impl-6б).
package evalharness

import (
	"context"
	"fmt"
	"math"
	"slices"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/evalset"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// LLMClassifier — минимальный интерфейс LLM-слоя (та же форма, что у
// scanengine.LLMClassifier): реализуется *agentproxy.Proxy и fake'ами тестов.
// nil → слой 2 отключён (прогон слоёв 0+1+ensemble, детерминирован, для CI).
type LLMClassifier interface {
	Classify(ctx context.Context, nativeType string, values []string) (*agentproxy.ClassifyResult, error)
	Verify(ctx context.Context, candidate, nativeType string, values []string) (*agentproxy.VerifyResult, error)
}

// Prices — цены модели за 1M токенов (blueprint п. 11.1). В контур harness'а
// store не входит, поэтому прайс задаётся извне (флаги cmd/eval); нули —
// учёт токенов без стоимости.
type Prices struct {
	In  float64 `json:"in"`  // $ за 1M входящих токенов
	Out float64 `json:"out"` // $ за 1M исходящих токенов
}

// Config — параметры прогона (пороги и веса — из detectors.yaml).
type Config struct {
	TauAccept float64 // правило 3 ансамбля (п. 7)
	TauReview float64 // нижняя граница серой зоны по умолчанию
	Weights   ensemble.Weights
	// Band — серая зона эскалации (confidence_band агента); нулевые →
	// [TauReview, TauAccept], как scanengine.grayBand (п. 5.6).
	Band [2]float64
	Meta *meta.Analyzer // слой 0; nil — слой выключен (как у движка)
	LLM  LLMClassifier  // слой 2; nil — LLM выключен
	// MinValuesForLLM — сэмпл меньше → вызов не делается (п. 7); 0 → 3.
	MinValuesForLLM int
	// NativeType — нативный тип колонок датасета для промпта LLM
	// (датасет значений не хранит типы); "" → "String".
	NativeType string
	Prices     Prices // учёт $ вызовов (п. 17)
}

// ColumnOutcome — результат классификации одной колонки датасета.
type ColumnOutcome struct {
	ID           string                `json:"id"`
	Truth        verdict.Label         `json:"truth"`
	Label        verdict.Label         `json:"label"` // предсказанный лейбл
	Confidence   float64               `json:"confidence"`
	Layer        verdict.EvidenceLayer `json:"layer"`
	ReviewStatus verdict.ReviewStatus  `json:"review_status"`
	LLMCalls     int                   `json:"llm_calls,omitempty"`
	LLMErrors    int                   `json:"llm_errors,omitempty"`

	// Candidates — кандидаты слоёв 0–1 (без LLM): sweep tau_accept
	// пересчитывает ансамбль по ним без повторных вызовов (metrics.go).
	Candidates []ensemble.Candidate `json:"-"`
}

// RunResult — итог прогона: исход по каждой колонке + экономика LLM-вызовов
// (blueprint п. 17; основа отчёта «$/1000 колонок»).
type RunResult struct {
	Outcomes  []ColumnOutcome
	LLMCalls  int
	LLMErrors int
	TokensIn  int
	TokensOut int
	CostUSD   float64
}

// Run прогоняет каскад по колонкам датасета в заданном порядке: слой 0
// (meta по имени) + слой 1 (rules) → ensemble.Decide (п. 7); при Escalate
// и включённом LLM — вызов классификатора, пересборка решения и при
// повторной серой зоне — верификатор с ApplyVerifier (правило 4) — зеркало
// scanengine.verdict. Отмена ctx прерывает прогон (обработанные колонки
// остаются в результирующем слайсе).
func Run(ctx context.Context, cols []evalset.Column, cfg Config) (*RunResult, error) {
	if cfg.TauAccept <= 0 || cfg.TauAccept > 1 {
		return nil, fmt.Errorf("evalharness: tau_accept должен быть в (0, 1], получено %v", cfg.TauAccept)
	}
	res := &RunResult{Outcomes: make([]ColumnOutcome, 0, len(cols))}
	recs := rules.Default()
	band := bandOf(cfg)
	for i := range cols {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Outcomes = append(res.Outcomes, classifyColumn(ctx, &cols[i], cfg, recs, band, res))
	}
	return res, nil
}

// classifyColumn — каскад для одной колонки датасета (значения датасета —
// это уже пул сэмпла: дедуп/усечение выполнил генератор, п. 16.6).
func classifyColumn(ctx context.Context, col *evalset.Column, cfg Config, recs []rules.Recognizer, band [2]float64, acc *RunResult) ColumnOutcome {
	out := ColumnOutcome{ID: col.ID, Truth: col.Label}
	if len(col.Values) == 0 { // small_sample (blueprint п. 6, п. 7)
		out.Label = verdict.Label("UNKNOWN")
		out.Layer = verdict.LayerEnsemble
		out.ReviewStatus = verdict.StatusPending
		return out
	}
	cands := make([]ensemble.Candidate, 0, 4)
	if cfg.Meta != nil {
		if l, c, ok := cfg.Meta.ByName(col.Name); ok {
			cands = append(cands, ensemble.Candidate{Label: l, Confidence: c, Layer: verdict.LayerMeta})
		}
	}
	for _, m := range rules.Analyze(col.Values, recs...) {
		cands = append(cands, ensemble.Candidate{Label: m.Label, Confidence: rules.Confidence(m), Layer: verdict.LayerRules})
	}
	out.Candidates = cands

	dec := ensemble.Decide(cands, cfg.TauAccept, cfg.Weights, band)
	if cfg.LLM != nil && dec.Escalate && enoughForLLM(col.Values, cfg) {
		out.runLLM(ctx, col.Values, cfg, band, acc, &dec)
	}
	out.Label = dec.Label
	out.Confidence = dec.Confidence
	out.Layer = dec.Layer
	out.ReviewStatus = dec.ReviewStatus
	return out
}

// runLLM — слой 2 поверх серой зоны: классификатор → пересборка решения →
// при повторной серой зоне верификатор (правило 4 п. 7). Учёт вызовов,
// токенов и $ — в acc (п. 10.6, п. 17). Ошибка вызова не роняет колонку:
// вердикт остаётся серым (как в движке).
func (out *ColumnOutcome) runLLM(ctx context.Context, values []string, cfg Config, band [2]float64, acc *RunResult, dec *ensemble.Outcome) {
	nativeType := cfg.NativeType
	if nativeType == "" {
		nativeType = "String"
	}
	res, err := cfg.LLM.Classify(ctx, nativeType, values)
	if err != nil || res == nil {
		out.LLMErrors++
		acc.LLMErrors++
		return
	}
	out.LLMCalls++
	acc.LLMCalls++
	acc.TokensIn += res.Usage.TokensIn
	acc.TokensOut += res.Usage.TokensOut
	acc.CostUSD = round6(acc.CostUSD + callCost(res.Usage.TokensIn, res.Usage.TokensOut, cfg.Prices))

	cands := append(slices.Clone(out.Candidates), ensemble.Candidate{
		Label: verdict.Label(res.Label), Confidence: res.Confidence, Layer: verdict.LayerLLM,
	})
	*dec = ensemble.Decide(cands, cfg.TauAccept, cfg.Weights, band)
	if !dec.Escalate {
		return
	}
	vr, err := cfg.LLM.Verify(ctx, string(dec.GrayBest.Label), nativeType, values)
	if err != nil || vr == nil {
		out.LLMErrors++
		acc.LLMErrors++
		return
	}
	out.LLMCalls++
	acc.LLMCalls++
	acc.TokensIn += vr.Usage.TokensIn
	acc.TokensOut += vr.Usage.TokensOut
	acc.CostUSD = round6(acc.CostUSD + callCost(vr.Usage.TokensIn, vr.Usage.TokensOut, cfg.Prices))
	*dec = ensemble.ApplyVerifier(*dec, ensemble.VerifierOutcome{
		Verdict: vr.Verdict, Label: verdict.Label(vr.Label), Confidence: vr.Confidence,
	}, cfg.TauAccept)
}

// callCost — стоимость вызова по прайсу (как scanengine.callCost, п. 11.1):
// округление до 6 знаков; нулевой прайс → 0 (учёт без цены, п. 17).
func callCost(tokensIn, tokensOut int, p Prices) float64 {
	cost := float64(tokensIn)/1e6*p.In + float64(tokensOut)/1e6*p.Out
	return math.Round(cost*1e6) / 1e6
}

// bandOf — серая зона эскалации: явная из конфигурации агента, иначе
// [TauReview, TauAccept] с дефолтами, как scanengine.grayBand.
func bandOf(cfg Config) [2]float64 {
	if cfg.Band[0] != 0 || cfg.Band[1] != 0 {
		return cfg.Band
	}
	lo := cfg.TauReview
	hi := cfg.TauAccept
	if lo <= 0 {
		lo = 0.3
	}
	if hi <= lo {
		hi = 0.7
	}
	return [2]float64{lo, hi}
}

// enoughForLLM — сэмпл меньше min значений → вызов не делается (п. 7).
func enoughForLLM(values []string, cfg Config) bool {
	min := cfg.MinValuesForLLM
	if min <= 0 {
		min = 3
	}
	return len(values) >= min
}
