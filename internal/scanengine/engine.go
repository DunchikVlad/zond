// Package scanengine — оркестрация скана: таблицы → сэмпл → каскад слоёв 0–1 →
// вердикты в store, чекпоинт после каждой таблицы (blueprint п. 7, п. 13).
// Этап 1: слои 0–1 + упрощённый ensemble; LLM-слой — этап 4; resume — позже (п. 13).
package scanengine

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/sampler"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Config — параметры движка, получаемые из detectors.yaml + taxonomy.yaml.
type Config struct {
	TauAccept        float64
	TauReview        float64
	Weights          map[string]float64 // meta | rules | llm (ensemble.weights)
	GrayBand         [2]float64         // confidence_band агента (серая зона)
	SampleMode       connector.SampleMode
	SampleValue      float64
	MaxRows          int64
	MaxStringChars   int
	Dedup            bool
	MinValuesForLLM  int // сэмпл меньше — LLM не вызывается (п. 7)
	TaxonomyVersion  string
	DetectorsVersion string
	Sensitivity      map[verdict.Label]verdict.Sensitivity
	TaxonomyLabels   []string // enum лейблов для промпта LLM
}

// LLMClassifier — минимальный интерфейс LLM-слоя для движка (п. 7).
// Реализуется agentproxy.Proxy; в тестах — fake. nil → слой 2 отключён.
type LLMClassifier interface {
	Classify(ctx context.Context, nativeType string, values []string) (*agentproxy.ClassifyResult, error)
	Verify(ctx context.Context, candidate, nativeType string, values []string) (*agentproxy.VerifyResult, error)
}

// Engine — движок сканирования одного источника.
type Engine struct {
	st    *store.Store
	meta  *meta.Analyzer
	recs  []rules.Recognizer
	llm   LLMClassifier // nil → слой 2 (LLM) отключён
	cfg   Config
	nowFn func() time.Time
}

// New собирает движок: recognizer'ы слоя 1 по умолчанию (rules.Default).
func New(st *store.Store, m *meta.Analyzer, cfg Config) *Engine {
	return &Engine{st: st, meta: m, recs: rules.Default(), cfg: cfg, nowFn: time.Now}
}

// SetLLM подключает LLM-слой (этап 4): серый коридор + эскалация (п. 7).
func (e *Engine) SetLLM(llm LLMClassifier) { e.llm = llm }

// Report — итог прогона (консольный отчёт этапа 1).
type Report struct {
	ScanID       string
	Source       string
	Profile      string
	Status       string
	StartedAt    time.Time
	FinishedAt   time.Time
	TablesTotal  int
	TablesDone   int
	TablesFailed int
	Verdicts     int
	Pending      int
	ByLabel      map[string]int
	ByLayer      map[string]int
	ByStatus     map[string]int
	Errors       []string
}

// Text печатает человекочитаемый отчёт.
func (r *Report) Text(w io.Writer) {
	fmt.Fprintf(w, "\n=== Скан %s — источник %s (профиль %s) ===\n", r.ScanID, r.Source, r.Profile)
	fmt.Fprintf(w, "Статус: %s   Длительность: %s\n", r.Status, r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "Таблицы: %d всего, %d обработано, %d с ошибками\n", r.TablesTotal, r.TablesDone, r.TablesFailed)
	fmt.Fprintf(w, "Вердикты: %d (ожидают ревью: %d)\n", r.Verdicts, r.Pending)
	fmt.Fprintf(w, "По слоям: %s\n", joinSorted(r.ByLayer))
	fmt.Fprintf(w, "По лейблам: %s\n", joinSorted(r.ByLabel))
	if len(r.Errors) > 0 {
		fmt.Fprintf(w, "Ошибки таблиц:\n")
		for _, e := range r.Errors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
}

func joinSorted(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

// Scan выполняет полный прогон по источнику (blueprint п. 13):
// недоступная таблица помечается failed и не роняет скан (п. 6).
func (e *Engine) Scan(ctx context.Context, conn connector.Connector, sourceName, profile string) (*Report, error) {
	scanID := newScanID(e.nowFn())
	rep := &Report{
		ScanID:    scanID,
		Source:    sourceName,
		Profile:   profile,
		Status:    "running",
		StartedAt: e.nowFn(),
		ByLabel:   map[string]int{},
		ByLayer:   map[string]int{},
		ByStatus:  map[string]int{},
	}
	if err := e.st.SaveScan(ctx, &store.Scan{
		ID: scanID, SourceName: sourceName, Profile: profile,
		Status: "running", StartedAt: rep.StartedAt,
	}); err != nil {
		return nil, fmt.Errorf("создание прогона: %w", err)
	}

	tables, err := conn.ListTables(ctx)
	if err != nil {
		e.finish(ctx, rep, "failed")
		return rep, fmt.Errorf("list tables: %w", err)
	}
	rep.TablesTotal = len(tables)

	for _, t := range tables {
		if err := e.scanTable(ctx, conn, scanID, t, rep); err != nil {
			// ошибка уже записана в scan_tables; продолжаем остальные таблицы
			rep.TablesFailed++
		} else {
			rep.TablesDone++
		}
	}

	status := "done"
	if rep.TablesFailed > 0 {
		status = "partial"
	}
	if err := e.aggregate(ctx, rep); err != nil {
		return rep, err
	}
	e.finish(ctx, rep, status)
	return rep, nil
}

func (e *Engine) finish(ctx context.Context, rep *Report, status string) {
	rep.Status = status
	rep.FinishedAt = e.nowFn()
	stats, _ := json.Marshal(map[string]any{
		"tables_total": rep.TablesTotal, "tables_done": rep.TablesDone,
		"tables_failed": rep.TablesFailed, "verdicts": rep.Verdicts,
		"by_layer": rep.ByLayer, "by_label": rep.ByLabel,
	})
	_ = e.st.FinishScan(ctx, rep.ScanID, status, string(stats), rep.FinishedAt)
}

func (e *Engine) aggregate(ctx context.Context, rep *Report) error {
	sum, err := e.st.VerdictSummary(ctx, rep.ScanID)
	if err != nil {
		return err
	}
	rep.Verdicts = sum.Total
	rep.Pending = sum.ByStatus["pending"]
	rep.ByLabel = sum.ByLabel
	rep.ByLayer = sum.ByLayer
	rep.ByStatus = sum.ByStatus
	failed, err := e.st.FailedTables(ctx, rep.ScanID)
	if err != nil {
		return err
	}
	rep.Errors = failed
	return nil
}

func (e *Engine) scanTable(ctx context.Context, conn connector.Connector, scanID string, t connector.TableRef, rep *Report) error {
	cols, err := conn.GetSchema(ctx, t)
	if err != nil {
		_ = e.st.MarkTable(ctx, scanID, t.Name, 0, "failed", err.Error())
		return err
	}
	var rowCount int64
	if n, err := conn.CountRows(ctx, t); err == nil {
		rowCount = n
	}
	vs := make([]verdict.Verdict, 0, len(cols))
	for _, col := range cols {
		v, err := e.classifyColumn(ctx, conn, scanID, t, col)
		if err != nil {
			// обрыв стрима сэмпла → таблица failed, чекпоинт (п. 6)
			_ = e.st.MarkTable(ctx, scanID, t.Name, rowCount, "failed", err.Error())
			return err
		}
		vs = append(vs, v)
	}
	if err := e.st.SaveVerdicts(ctx, vs); err != nil {
		_ = e.st.MarkTable(ctx, scanID, t.Name, rowCount, "failed", err.Error())
		return err
	}
	return e.st.MarkTable(ctx, scanID, t.Name, rowCount, "done", "")
}

func (e *Engine) classifyColumn(ctx context.Context, conn connector.Connector, scanID string, t connector.TableRef, col connector.Column) (verdict.Verdict, error) {
	seq, err := conn.Sample(ctx, connector.SampleSpec{
		Table:   t,
		Mode:    e.cfg.SampleMode,
		Value:   e.cfg.SampleValue,
		Columns: []string{col.Name},
		MaxRows: e.cfg.MaxRows,
	})
	if err != nil {
		return verdict.Verdict{}, err
	}
	pool, err := sampler.Build(seq, col.Name, sampler.Options{
		MaxRows:        e.cfg.MaxRows,
		MaxStringChars: e.cfg.MaxStringChars,
		Dedup:          e.cfg.Dedup,
	})
	if err != nil {
		return verdict.Verdict{}, err
	}
	return e.verdict(ctx, scanID, t, col, pool), nil
}

// verdict собирает вердикт колонки: слой 0 (имя) + слой 1 (rules) + слой 2 (LLM,
// серый коридор) → ensemble (п. 7).
func (e *Engine) verdict(ctx context.Context, scanID string, t connector.TableRef, col connector.Column, pool *sampler.Pool) verdict.Verdict {
	sum := sha1.Sum([]byte(scanID + "|" + t.Name + "|" + col.Name)) // п. 5.4
	v := verdict.Verdict{
		ID:               hex.EncodeToString(sum[:]),
		ScanID:           scanID,
		Table:            t.Name,
		Path:             col.Name,
		NativeType:       col.NativeType,
		SampleSize:       len(pool.Values),
		TaxonomyVersion:  e.cfg.TaxonomyVersion,
		DetectorsVersion: e.cfg.DetectorsVersion,
		Sensitivity:      e.cfg.Sensitivity[verdict.Label("UNKNOWN")],
		CreatedAt:        e.nowFn(),
	}

	cands := make([]ensemble.Candidate, 0, 4)
	if e.meta != nil {
		if l, c, ok := e.meta.ByName(col.Name); ok {
			cands = append(cands, ensemble.Candidate{Label: l, Confidence: c, Layer: verdict.LayerMeta})
		}
	}
	matches := rules.Analyze(pool.Values, e.recs...)
	evRules := map[string]any{}
	for _, m := range matches {
		cands = append(cands, ensemble.Candidate{Label: m.Label, Confidence: rules.Confidence(m), Layer: verdict.LayerRules})
		evRules[m.RecognizerID] = map[string]any{
			"matched": m.Matched, "total": m.Total, "checksum": m.HasChecksum,
		}
	}

	// слой 2 (LLM) — только серый коридор и достаточный сэмпл (п. 7);
	// small_sample или null>0.95 → вызов не делается.
	gray := e.grayBand()
	weights := ensemble.Weights{}
	for k, wgt := range e.cfg.Weights {
		weights[verdict.EvidenceLayer(k)] = wgt
	}
	out := ensemble.Decide(cands, e.cfg.TauAccept, weights, gray)

	// серый коридор: вызов LLM-классификатора (этап 4), затем эскалация.
	if e.llm != nil && out.Escalate && e.enoughForLLM(pool) {
		if res, err := e.llm.Classify(ctx, col.NativeType, pool.Values); err == nil && res != nil {
			v.PromptVersion = res.PromptVersion
			cands = append(cands, ensemble.Candidate{Label: verdict.Label(res.Label), Confidence: res.Confidence, Layer: verdict.LayerLLM})
			out = ensemble.Decide(cands, e.cfg.TauAccept, weights, gray)
		}
		// эскалация в верификатор, если решение всё ещё в серой зоне (п. 7 правило 4)
		if out.Escalate {
			if vr, err := e.llm.Verify(ctx, string(out.GrayBest.Label), col.NativeType, pool.Values); err == nil && vr != nil {
				out = ensemble.ApplyVerifier(out, ensemble.VerifierOutcome{
					Verdict: vr.Verdict, Label: verdict.Label(vr.Label), Confidence: vr.Confidence,
				}, e.cfg.TauAccept)
			}
		}
	}
	v.Label = out.Label
	v.Confidence = out.Confidence
	v.EvidenceLayer = out.Layer
	v.ReviewStatus = out.ReviewStatus
	if s, ok := e.cfg.Sensitivity[out.Label]; ok {
		v.Sensitivity = s
	}
	v.Evidence = map[string]any{
		"rules":  evRules,
		"sample": map[string]any{"values": len(pool.Values), "nulls": pool.Nulls, "total": pool.Total, "skipped": pool.Skipped},
	}
	if len(pool.Values) == 0 || (pool.Total > 0 && float64(pool.Nulls)/float64(pool.Total) > 0.95) {
		v.Label = verdict.Label("UNKNOWN")
		v.ReviewStatus = verdict.StatusPending
		v.Evidence["reason"] = "small_sample"
	}
	return v
}

// grayBand — серая зона confidence для LLM/эскалации (confidence_band агента).
// По умолчанию [tau_review, tau_accept] если явно не задана.
func (e *Engine) grayBand() [2]float64 {
	if e.cfg.GrayBand[0] != 0 || e.cfg.GrayBand[1] != 0 {
		return e.cfg.GrayBand
	}
	lo := e.cfg.TauReview
	hi := e.cfg.TauAccept
	if lo <= 0 {
		lo = 0.3
	}
	if hi <= lo {
		hi = 0.7
	}
	return [2]float64{lo, hi}
}

// enoughForLLM — достаточно ли значений для вызова LLM (п. 7: сэмпл <
// min_values_for_llm или null>0.95 → вызов не делается).
func (e *Engine) enoughForLLM(pool *sampler.Pool) bool {
	min := e.cfg.MinValuesForLLM
	if min <= 0 {
		min = 3
	}
	if len(pool.Values) < min {
		return false
	}
	if pool.Total > 0 && float64(pool.Nulls)/float64(pool.Total) > 0.95 {
		return false
	}
	return true
}

// newScanID — уникальный id прогона (время + случайность).
func newScanID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%d-%s", now.Unix(), hex.EncodeToString(b[:]))
}
