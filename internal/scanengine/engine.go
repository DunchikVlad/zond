// Package scanengine — оркестрация скана: таблицы → сэмпл → каскад слоёв 0–1 →
// вердикты в store, чекпоинт после каждой таблицы (blueprint п. 7, п. 13).
// Этап 1: слои 0–1 + упрощённый ensemble; LLM-слой — этап 4; resume — позже (п. 13).
package scanengine

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/agentproxy/mask"
	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
	"github.com/DunchikVlad/zond/internal/analyze/cluster"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/fingerprint"
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

	// Инкремент 4б: кэш вердиктов (п. 10.5) и кластеризация (п. 7.6).
	CacheScope        string // "agent_id|model" — идентичность агента в ключе кэша; "" → кэш выключен
	Clustering        bool   // кластеризация колонок до слоя 2
	ClusterSimilarity float64
	ClusterMaxSize    int
}

// LLMClassifier — минимальный интерфейс LLM-слоя для движка (п. 7).
// Реализуется agentproxy.Proxy; в тестах — fake. nil → слой 2 отключён.
type LLMClassifier interface {
	Classify(ctx context.Context, nativeType string, values []string) (*agentproxy.ClassifyResult, error)
	Verify(ctx context.Context, candidate, nativeType string, values []string) (*agentproxy.VerifyResult, error)
}

// Engine — движок сканирования одного источника.
type Engine struct {
	st        *store.Store
	meta      *meta.Analyzer
	recs      []rules.Recognizer
	llm       LLMClassifier // nil → слой 2 (LLM) отключён
	cfg       Config
	nowFn     func() time.Time
	clusterer *cluster.Clusterer // на скан (п. 7.6); nil — кластеризация выключена
	stats     scanStats          // счётчики экономики текущего прогона
}

// scanStats — счётчики экономики сканирования (blueprint п. 17).
type scanStats struct {
	llmCalls   int // реальные вызовы LLM
	cacheHits  int // вердикты из кэша (п. 10.5)
	propagated int // вердикты из кластера (п. 7.6)
}

// New собирает движок: recognizer'ы слоя 1 по умолчанию (rules.Default).
func New(st *store.Store, m *meta.Analyzer, cfg Config) *Engine {
	return &Engine{st: st, meta: m, recs: rules.Default(), cfg: cfg, nowFn: time.Now}
}

// SetLLM подключает LLM-слой (этап 4): серый коридор + эскалация (п. 7).
func (e *Engine) SetLLM(llm LLMClassifier) { e.llm = llm }

// Report — итог прогона (консольный отчёт этапа 1).
type Report struct {
	ScanID            string
	Source            string
	Profile           string
	Status            string
	StartedAt         time.Time
	FinishedAt        time.Time
	TablesTotal       int
	TablesDone        int
	TablesFailed      int
	Verdicts          int
	Pending           int
	ByLabel           map[string]int
	ByLayer           map[string]int
	ByStatus          map[string]int
	LLMCalls          int // экономика: реальные вызовы LLM (п. 17)
	CacheHits         int // вердикты из кэша (п. 10.5)
	ClusterPropagated int // вердикты из кластеров (п. 7.6)
	Errors            []string
}

// Text печатает человекочитаемый отчёт.
func (r *Report) Text(w io.Writer) {
	fmt.Fprintf(w, "\n=== Скан %s — источник %s (профиль %s) ===\n", r.ScanID, r.Source, r.Profile)
	fmt.Fprintf(w, "Статус: %s   Длительность: %s\n", r.Status, r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "Таблицы: %d всего, %d обработано, %d с ошибками\n", r.TablesTotal, r.TablesDone, r.TablesFailed)
	fmt.Fprintf(w, "Вердикты: %d (ожидают ревью: %d)\n", r.Verdicts, r.Pending)
	fmt.Fprintf(w, "По слоям: %s\n", joinSorted(r.ByLayer))
	fmt.Fprintf(w, "По лейблам: %s\n", joinSorted(r.ByLabel))
	if r.LLMCalls+r.CacheHits+r.ClusterPropagated > 0 {
		fmt.Fprintf(w, "Экономика: LLM-вызовов %d, из кэша %d, из кластеров %d\n",
			r.LLMCalls, r.CacheHits, r.ClusterPropagated)
	}
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
	if e.cfg.Clustering {
		e.clusterer = cluster.New(e.cfg.ClusterSimilarity, e.cfg.ClusterMaxSize)
	} else {
		e.clusterer = nil
	}
	e.stats = scanStats{}

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
	rep.LLMCalls = e.stats.llmCalls
	rep.CacheHits = e.stats.cacheHits
	rep.ClusterPropagated = e.stats.propagated
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
		"llm_calls": rep.LLMCalls, "cache_hits": rep.CacheHits,
		"cluster_propagated": rep.ClusterPropagated,
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

	// Кластеризация до слоя 2 (п. 7.6): отпечаток по маскированным значениям;
	// член кластера с известным вердиктом представителя получает его копию.
	maskedVals := maskedForFingerprint(pool.Values)
	feat := fingerprint.Compute(col.NativeType, maskedVals, pool.Total, pool.Nulls)
	v.ClusterID = ""
	propagated := false
	if e.clusterer != nil {
		if id, ok := e.clusterer.Find(feat); ok {
			v.ClusterID = id
			if pv, ok := e.clusterer.Verdict(id); ok {
				applyClusterVerdict(&v, pv)
				propagated = true
				e.stats.propagated++
			} else {
				e.clusterer.Attach(id)
			}
		} else {
			v.ClusterID = e.clusterer.Register(feat)
		}
	}
	if propagated {
		e.finalizeVerdict(&v, pool, evRules)
		v.Evidence["cluster_propagated"] = true
		return v
	}

	// слой 2 (LLM) — только серый коридор и достаточный сэмпл (п. 7);
	// small_sample или null>0.95 → вызов не делается.
	gray := e.grayBand()
	weights := ensemble.Weights{}
	for k, wgt := range e.cfg.Weights {
		weights[verdict.EvidenceLayer(k)] = wgt
	}
	out := ensemble.Decide(cands, e.cfg.TauAccept, weights, gray)

	// серый коридор: вызов LLM-классификатора (этап 4) с кэшем вердиктов
	// (п. 10.5), затем эскалация в верификатор.
	if e.llm != nil && out.Escalate && e.enoughForLLM(pool) {
		if res := e.llmClassify(ctx, col, pool, maskedVals, &v); res != nil {
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
	e.finalizeVerdict(&v, pool, evRules)
	if v.ClusterID != "" && e.clusterer != nil {
		// вердикт представителя — источник для распространения (п. 7.6)
		e.clusterer.SetVerdict(v.ClusterID, cluster.VerdictView{
			Label: string(v.Label), Confidence: v.Confidence,
			Layer: string(v.EvidenceLayer), ReviewStatus: string(v.ReviewStatus),
		})
	}
	return v
}

// finalizeVerdict — общий хвост: sensitivity из таксономии, evidence,
// жёсткие правила small_sample (п. 6, п. 7). Evidence уже может содержать
// записи (llm_cache) — пополняется, не пересоздаётся.
func (e *Engine) finalizeVerdict(v *verdict.Verdict, pool *sampler.Pool, evRules map[string]any) {
	if s, ok := e.cfg.Sensitivity[v.Label]; ok {
		v.Sensitivity = s
	}
	if v.Evidence == nil {
		v.Evidence = map[string]any{}
	}
	v.Evidence["rules"] = evRules
	v.Evidence["sample"] = map[string]any{"values": len(pool.Values), "nulls": pool.Nulls, "total": pool.Total, "skipped": pool.Skipped}
	if len(pool.Values) == 0 || (pool.Total > 0 && float64(pool.Nulls)/float64(pool.Total) > 0.95) {
		v.Label = verdict.Label("UNKNOWN")
		v.ReviewStatus = verdict.StatusPending
		v.Evidence["reason"] = "small_sample"
	}
}

// applyClusterVerdict переносит вердикт представителя на члена кластера (п. 7.6).
func applyClusterVerdict(v *verdict.Verdict, pv cluster.VerdictView) {
	v.Label = verdict.Label(pv.Label)
	v.Confidence = pv.Confidence
	v.EvidenceLayer = verdict.EvidenceLayer(pv.Layer)
	v.ReviewStatus = verdict.ReviewStatus(pv.ReviewStatus)
}

// maskedForFingerprint маскирует значения пула для отпечатка (п. 7.6:
// префикс/суффикс — по маскированным значениям). Короткие (< MinLen) → "".
func maskedForFingerprint(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if m, ok := mask.Mask(v); ok {
			out = append(out, m)
		} else {
			out = append(out, "")
		}
	}
	return out
}

// cachedLLMVerdict — JSON-представление ответа классификатора в кэше (п. 10.5).
// Только лейбл/уверенность/версия промпта — без значений (ADR-0010).
type cachedLLMVerdict struct {
	Label         string  `json:"label"`
	Confidence    float64 `json:"confidence"`
	PromptVersion string  `json:"prompt_version"`
}

// llmClassify вызывает LLM-классификатора с кэшем вердиктов (п. 10.5): при
// промахе — вызов и запись в кэш (TTL CacheTTLDefault), при попадании —
// вердикт без сетевого обращения. Возвращает nil при ошибке вызова.
func (e *Engine) llmClassify(ctx context.Context, col connector.Column, pool *sampler.Pool, maskedVals []string, v *verdict.Verdict) *agentproxy.ClassifyResult {
	cacheKey := ""
	if e.cfg.CacheScope != "" {
		cacheKey = llmCacheKey(e.cfg.CacheScope, e.cfg.TaxonomyVersion, fingerprint.ValuesHash(maskedVals))
		if cv, ok, err := e.st.CacheGet(ctx, cacheKey, e.nowFn()); err == nil && ok {
			if cached, err := decodeCachedVerdict(cv.VerdictJSON); err == nil {
				e.stats.cacheHits++
				setLLMCacheEvidence(v, cv.AgentID, true)
				return cached
			}
		}
	}
	res, err := e.llm.Classify(ctx, col.NativeType, pool.Values)
	if err != nil || res == nil {
		return nil
	}
	e.stats.llmCalls++
	v.PromptVersion = res.PromptVersion
	if cacheKey != "" {
		if b, mErr := json.Marshal(cachedLLMVerdict{
			Label: res.Label, Confidence: res.Confidence, PromptVersion: res.PromptVersion,
		}); mErr == nil {
			now := e.nowFn()
			_ = e.st.CachePut(ctx, cacheKey, store.CachedVerdict{
				AgentID:     cacheAgentID(e.cfg.CacheScope),
				VerdictJSON: string(b),
				CreatedAt:   now,
				ExpiresAt:   now.Add(store.CacheTTLDefault),
			})
		}
		setLLMCacheEvidence(v, cacheAgentID(e.cfg.CacheScope), false)
	}
	return res
}

func setLLMCacheEvidence(v *verdict.Verdict, agentID string, hit bool) {
	if v.Evidence == nil {
		v.Evidence = map[string]any{}
	}
	v.Evidence["llm_cache"] = map[string]any{"hit": hit, "agent_id": agentID}
}

func decodeCachedVerdict(s string) (*agentproxy.ClassifyResult, error) {
	var cv cachedLLMVerdict
	if err := json.Unmarshal([]byte(s), &cv); err != nil {
		return nil, err
	}
	return &agentproxy.ClassifyResult{
		Label: cv.Label, Confidence: cv.Confidence, PromptVersion: cv.PromptVersion,
	}, nil
}

// llmCacheKey — составной ключ кэша (blueprint п. 10.5):
// sha256(agent_id | model | prompt_version | taxonomy_version |
// mask_profile_version | fingerprint(values)).
func llmCacheKey(scope, taxonomyVersion, valuesHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"llm-classify", scope, prompts.Version, taxonomyVersion, mask.Version, valuesHash,
	}, "|")))
	return hex.EncodeToString(sum[:])
}

// cacheAgentID — часть CacheScope до '|' (agent_id для записи кэша).
func cacheAgentID(scope string) string {
	if i := strings.IndexByte(scope, '|'); i >= 0 {
		return scope[:i]
	}
	return scope
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
