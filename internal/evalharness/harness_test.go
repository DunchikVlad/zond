// Тесты eval-harness'а: каскад слоёв 0–2 по синтетическому датасету с
// ручным расчётом метрик, sweep tau_accept, LLM-контур на fake, экономика
// и детерминизм отчёта (blueprint п. 16.6).
package evalharness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/evalset"
)

// testSynonyms — минимальный словарь слоя 0 для тестов.
func testSynonyms() map[string][]string {
	return map[string][]string{
		"EMAIL":  {"email"},
		"TAX_ID": {"inn"},
	}
}

// testDataset — 6 колонок с детерминированным результатом каскада:
// c0 EMAIL (meta+rules, auto), c1 TAX_ID (checksum 0.99, rules auto),
// c2 спуф ИНН-12 (meta по имени "inn_raw" → ложный TAX_ID; 12 цифр не
// коллидируют с форматом паспорта 10 цифр — в отличие от ИНН-10),
// c3 free_text со встроенным телефоном (нет кандидатов → UNKNOWN pending),
// c4 mixed chaos (UNKNOWN pending), c5 даты рождения (rules даёт DATE_TIME).
func testDataset() []evalset.Column {
	emails := []string{"ivan@example.com", "petr@example.com", "anna@example.com", "boris@example.com", "olga@example.com"}
	innOK := []string{"7707083893", "7707083893", "7707083893", "7707083893", "7707083893"}
	// ИНН-12 "770400123459" валиден; "...458" — испорчена вторая контрольная.
	innBad := []string{"770400123458", "770400123458", "770400123458", "770400123458", "770400123458"}
	freeText := []string{
		"позвоните +7 999 123-45-67 завтра",
		"мой телефон 8 (999) 123-45-67",
		"не номер 12345",
		"просто текст без цифр",
		"встреча у метро в пять",
	}
	chaos := []string{"42", "true", `{"a":1}`, "3.14", "null"}
	dates := []string{"1990-05-17", "1985-11-02", "1977-01-30", "2000-12-05", "1993-07-21"}
	return []evalset.Column{
		{ID: "c0", Name: "email", Label: "EMAIL", Kind: evalset.KindPositive, Values: emails},
		{ID: "c1", Name: "field1", Label: "TAX_ID", Kind: evalset.KindPositive, Values: innOK},
		{ID: "c2", Name: "inn_raw", Label: "UNKNOWN", Kind: evalset.KindSpoof, Spoofs: "TAX_ID", Values: innBad},
		{ID: "c3", Name: "field2", Label: "FREE_TEXT", Kind: evalset.KindFreeText, Values: freeText},
		{ID: "c4", Name: "field3", Label: "UNKNOWN", Kind: evalset.KindMixed, Values: chaos},
		{ID: "c5", Name: "dob", Label: "DATE_OF_BIRTH", Kind: evalset.KindPositive, Values: dates},
	}
}

func testConfig(llm LLMClassifier) Config {
	return Config{
		TauAccept: 0.8,
		TauReview: 0.5,
		Weights:   ensemble.Weights{"meta": 1.0, "rules": 1.5},
		Band:      [2]float64{0.5, 0.8},
		Meta:      meta.New(testSynonyms()),
		LLM:       llm,
	}
}

func runTest(t *testing.T, cols []evalset.Column, cfg Config) *RunResult {
	t.Helper()
	rr, err := Run(context.Background(), cols, cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rr.Outcomes) != len(cols) {
		t.Fatalf("исходов %d ≠ колонок %d", len(rr.Outcomes), len(cols))
	}
	return rr
}

func outcomeByID(t *testing.T, rr *RunResult, id string) ColumnOutcome {
	t.Helper()
	for _, o := range rr.Outcomes {
		if o.ID == id {
			return o
		}
	}
	t.Fatalf("исход колонки %s не найден", id)
	return ColumnOutcome{}
}

// TestRunRulesOnly — ожидания по каскаду посчитаны вручную (см. комментарий
// testDataset): метрики, статусы ревью, разрезы по видам и спуфам.
func TestRunRulesOnly(t *testing.T) {
	cols := testDataset()
	rr := runTest(t, cols, testConfig(nil))

	wantLabels := map[string]string{
		"c0": "EMAIL", "c1": "TAX_ID", "c2": "TAX_ID",
		"c3": "UNKNOWN", "c4": "UNKNOWN", "c5": "DATE_TIME",
	}
	for id, want := range wantLabels {
		if o := outcomeByID(t, rr, id); string(o.Label) != want {
			t.Errorf("%s: лейбл %s, ожидался %s", id, o.Label, want)
		}
	}
	if o := outcomeByID(t, rr, "c1"); o.Layer != "rules" || o.ReviewStatus != "auto_accepted" {
		t.Errorf("c1: слой/статус %s/%s, ожидалось rules/auto_accepted (checksum 0.99)", o.Layer, o.ReviewStatus)
	}
	if o := outcomeByID(t, rr, "c3"); o.ReviewStatus != "pending" {
		t.Errorf("c3: статус %s, ожидалось pending (нет кандидатов)", o.ReviewStatus)
	}

	rep := BuildReport(&evalset.Manifest{Dataset: "1.0.0", Taxonomy: "1.0.0", Seed: 1}, cols, rr, testConfig(nil), nil, "test", "", "")
	if rep.Columns != 6 {
		t.Errorf("Columns=%d, ожидалось 6", rep.Columns)
	}
	// EMAIL идеален; TAX_ID: TP=1 FP=1 (спуф c2); UNKNOWN: TP=1 (c4) FP=1
	// (free_text c3) FN=1 (спуф c2); FREE_TEXT и DATE_OF_BIRTH без recall;
	// DATE_TIME — ложный позитив rules (даты рождения c5).
	assertStat := func(l string, tp, fp, fn int, p, r, f1 float64) {
		t.Helper()
		s := rep.Labels[l]
		if s == nil {
			t.Fatalf("лейбл %s отсутствует в отчёте", l)
		}
		if s.TP != tp || s.FP != fp || s.FN != fn {
			t.Errorf("%s: tp/fp/fn = %d/%d/%d, ожидалось %d/%d/%d", l, s.TP, s.FP, s.FN, tp, fp, fn)
		}
		if s.Precision != p || s.Recall != r || s.F1 != f1 {
			t.Errorf("%s: P/R/F1 = %v/%v/%v, ожидалось %v/%v/%v", l, s.Precision, s.Recall, s.F1, p, r, f1)
		}
	}
	assertStat("EMAIL", 1, 0, 0, 1, 1, 1)
	assertStat("TAX_ID", 1, 1, 0, 0.5, 1, 0.6667)
	assertStat("UNKNOWN", 1, 1, 1, 0.5, 0.5, 0.5)
	assertStat("FREE_TEXT", 0, 0, 1, 0, 0, 0)
	assertStat("DATE_OF_BIRTH", 0, 0, 1, 0, 0, 0)
	assertStat("DATE_TIME", 0, 1, 0, 0, 0, 0)
	// micro: TP=3 FP=3 FN=3 → P=R=F1=0.5.
	if rep.Micro.F1 != 0.5 {
		t.Errorf("micro F1 = %v, ожидалось 0.5", rep.Micro.F1)
	}
	if rep.MacroF1 != 0.3611 {
		t.Errorf("macro F1 = %v, ожидалось 0.3611", rep.MacroF1)
	}
	// разрез по видам: positive 2/3, spoof 0/1, free_text 0/1, mixed 1/1.
	assertKind := func(k string, total, correct int, acc float64) {
		t.Helper()
		ks := rep.ByKind[k]
		if ks == nil || ks.Total != total || ks.Correct != correct || ks.Accuracy != acc {
			t.Errorf("by_kind[%s] = %+v, ожидалось total=%d correct=%d acc=%v", k, ks, total, correct, acc)
		}
	}
	assertKind("positive", 3, 2, 0.6667)
	assertKind("spoof", 1, 0, 0)
	assertKind("free_text", 1, 0, 0)
	assertKind("mixed", 1, 1, 1)
	// спуф-precision TAX_ID = 0 (единственный спуф отнесён к TAX_ID meta-слоем).
	ss := rep.Spoofs["TAX_ID"]
	if ss == nil || ss.Total != 1 || ss.Mispredicted != 1 || ss.SpoofPrecision != 0 {
		t.Errorf("spoofs[TAX_ID] = %+v, ожидалось total=1 mispredicted=1 precision=0", ss)
	}
	if rep.Review["auto_accepted"] != 4 || rep.Review["pending"] != 2 {
		t.Errorf("review_status = %v, ожидалось auto=4 pending=2", rep.Review)
	}
	if rep.Econ != nil {
		t.Errorf("экономика без LLM должна отсутствовать: %+v", rep.Econ)
	}
}

// TestSweep — лейблы без LLM инвариантны к tau (лучший кандидат всегда
// побеждает), поэтому sweep показывает trade-off auto_accepted ↔ F1(decided):
// 0.50/0.80 → auto=4, 0.95 → auto=1 (только checksum ИНН; решающее подмножество
// {c0,c1,c2,c5}: TP=2, FP=2 (спуф c2 + DATE_TIME c5), FN=2 → F1=0.5).
func TestSweep(t *testing.T) {
	cols := testDataset()
	cfg := testConfig(nil)
	rr := runTest(t, cols, cfg)
	grid := []float64{0.5, 0.8, 0.95}
	rep := BuildReport(&evalset.Manifest{Dataset: "1.0.0", Taxonomy: "1.0.0"}, cols, rr, cfg, grid, "test", "", "")
	if len(rep.Sweep) != 3 {
		t.Fatalf("строк sweep %d ≠ 3", len(rep.Sweep))
	}
	r0, r1, r2 := rep.Sweep[0], rep.Sweep[1], rep.Sweep[2]
	if r0.AutoAccepted != 4 || r0.Pending != 2 || r1.AutoAccepted != 4 || r2.AutoAccepted != 1 || r2.Pending != 5 {
		t.Errorf("auto/pending: (%d,%d) (%d,.) (,%d), ожидалось (4,2) (4,.) (1,5)",
			r0.AutoAccepted, r0.Pending, r1.AutoAccepted, r2.Pending)
	}
	if r0.F1All != r1.F1All || r1.F1All != r2.F1All {
		t.Errorf("F1All меняется с tau: %v %v %v (без LLM лейбл инвариантен)", r0.F1All, r1.F1All, r2.F1All)
	}
	if r2.F1Decided != 1 {
		t.Errorf("F1Decided при tau=0.95 = %v, ожидалось 1 (решён только checksum-ИНН)", r2.F1Decided)
	}
	if r0.F1Decided != 0.5 {
		t.Errorf("F1Decided при tau=0.50 = %v, ожидалось 0.5 (TP=2 FP=2 FN=2)", r0.F1Decided)
	}
}

// fakeLLM — LLMClassifier с заданными ответами и учётом вызовов.
type fakeLLM struct {
	classifyRes   *agentproxy.ClassifyResult
	classifyErr   error
	verifyRes     *agentproxy.VerifyResult
	verifyErr     error
	classifyCalls int
	verifyCalls   int
	lastCandidate string
}

func (f *fakeLLM) Classify(_ context.Context, _ string, _ []string) (*agentproxy.ClassifyResult, error) {
	f.classifyCalls++
	return f.classifyRes, f.classifyErr
}

func (f *fakeLLM) Verify(_ context.Context, candidate, _ string, _ []string) (*agentproxy.VerifyResult, error) {
	f.verifyCalls++
	f.lastCandidate = candidate
	return f.verifyRes, f.verifyErr
}

// grayEmailColumn — колонка в серой зоне: rules EMAIL поймал 2/5 значений
// (confidence 0.50), meta молчит (имя нейтральное) → эскалация в LLM.
func grayEmailColumn() evalset.Column {
	return evalset.Column{
		ID: "g0", Name: "field9", Label: "EMAIL", Kind: evalset.KindPositive,
		Values: []string{"ivan@example.com", "petr@example.com", "не почта", "просто текст", "ещё текст"},
	}
}

// TestLLMCascade — эскалация: classify (0.9) не достаёт до tau → verify
// confirm → auto_accepted (правило 4 п. 7); токены/$ учтены, per-1000
// нормировано.
func TestLLMCascade(t *testing.T) {
	fake := &fakeLLM{
		classifyRes: &agentproxy.ClassifyResult{Label: "EMAIL", Confidence: 0.9, Usage: agentproxy.Usage{TokensIn: 100, TokensOut: 20}},
		verifyRes:   &agentproxy.VerifyResult{Verdict: "confirm", Label: "EMAIL", Confidence: 0.95, Usage: agentproxy.Usage{TokensIn: 50, TokensOut: 10}},
	}
	cols := []evalset.Column{grayEmailColumn()}
	cfg := testConfig(fake)
	cfg.Prices = Prices{In: 2, Out: 10}
	rr := runTest(t, cols, cfg)

	o := outcomeByID(t, rr, "g0")
	if o.Label != "EMAIL" || o.ReviewStatus != "auto_accepted" || o.Layer != "llm" {
		t.Errorf("g0: %s/%s/%s, ожидалось EMAIL/auto_accepted/llm", o.Label, o.ReviewStatus, o.Layer)
	}
	if fake.classifyCalls != 1 || fake.verifyCalls != 1 || fake.lastCandidate != "EMAIL" {
		t.Errorf("вызовы classify/verify/candidate = %d/%d/%q, ожидалось 1/1/EMAIL",
			fake.classifyCalls, fake.verifyCalls, fake.lastCandidate)
	}
	if rr.LLMCalls != 2 || rr.TokensIn != 150 || rr.TokensOut != 30 {
		t.Errorf("экономика: вызовов %d, токены %d/%d, ожидалось 2 и 150/30", rr.LLMCalls, rr.TokensIn, rr.TokensOut)
	}
	// cost = 150/1e6*2 + 30/1e6*10 = 0.0006.
	if rr.CostUSD != 0.0006 {
		t.Errorf("CostUSD = %v, ожидалось 0.0006", rr.CostUSD)
	}
	rep := BuildReport(&evalset.Manifest{Dataset: "1.0.0", Taxonomy: "1.0.0"}, cols, rr, cfg, nil, "test", "fake-agent", "fake-model")
	if rep.Econ == nil {
		t.Fatal("экономика в отчёте отсутствует")
	}
	if !rep.Econ.PricesSet || rep.Econ.Per1000.TokensIn != 150000 || rep.Econ.Per1000.CostUSD != 0.6 {
		t.Errorf("per-1000: %+v, ожидалось tokens_in=150000 cost=0.6 prices_set=true", rep.Econ.Per1000)
	}
	if rep.Config.LLM != true || rep.Config.AgentID != "fake-agent" || rep.Config.Model != "fake-model" {
		t.Errorf("config-ref LLM/agent/model = %v/%s/%s", rep.Config.LLM, rep.Config.AgentID, rep.Config.Model)
	}
}

// TestLLMErrorsAndSmallSample — ошибка classify не роняет колонку (вердикт
// остаётся серым pending), счётчик ошибок растёт; пустая колонка —
// small_sample → UNKNOWN pending, LLM не вызывается.
func TestLLMErrorsAndSmallSample(t *testing.T) {
	fake := &fakeLLM{classifyErr: errors.New("сеть недоступна")}
	cols := []evalset.Column{
		grayEmailColumn(),
		{ID: "e0", Name: "empty", Label: "EMAIL", Kind: evalset.KindPositive, Values: nil},
	}
	rr := runTest(t, cols, testConfig(fake))

	o := outcomeByID(t, rr, "g0")
	if o.Label != "EMAIL" || o.ReviewStatus != "pending" || o.LLMErrors != 1 {
		t.Errorf("g0: %s/%s ошибок=%d, ожидалось EMAIL/pending/1", o.Label, o.ReviewStatus, o.LLMErrors)
	}
	if rr.LLMErrors != 1 {
		t.Errorf("LLMErrors = %d, ожидалось 1", rr.LLMErrors)
	}
	e := outcomeByID(t, rr, "e0")
	if e.Label != "UNKNOWN" || e.ReviewStatus != "pending" || e.LLMCalls != 0 || e.LLMErrors != 0 {
		t.Errorf("e0: %s/%s вызовов=%d, ожидалось UNKNOWN/pending/0", e.Label, e.ReviewStatus, e.LLMCalls)
	}
	if fake.classifyCalls != 1 {
		t.Errorf("classify вызван %d раз, ожидалось 1 (small_sample не дёргает LLM)", fake.classifyCalls)
	}
}

// TestRunValidation — tau_accept вне (0,1] отклоняется до прогона.
func TestRunValidation(t *testing.T) {
	cfg := testConfig(nil)
	cfg.TauAccept = 0
	if _, err := Run(context.Background(), testDataset(), cfg); err == nil {
		t.Error("tau_accept=0: ожидалась ошибка")
	}
}

// TestReportDeterministicAndRoundTrip — два отчёта по одним данным
// сериализуются побайтово одинаково; WriteReport → JSON читается обратно.
func TestReportDeterministicAndRoundTrip(t *testing.T) {
	cols := testDataset()
	cfg := testConfig(nil)
	rr := runTest(t, cols, cfg)
	grid := []float64{0.5, 0.8, 0.95}
	m := &evalset.Manifest{Dataset: "1.0.0", Taxonomy: "1.0.0", Seed: 42, Counts: evalset.Counts{ByLabel: map[string]int{}, ByKind: map[string]int{}}}
	r1 := BuildReport(m, cols, rr, cfg, grid, "test", "", "")
	r2 := BuildReport(m, cols, rr, cfg, grid, "test", "", "")
	b1, err := json.Marshal(r1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b2, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Error("отчёты по одним данным сериализовались по-разному")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "report.json")
	if err := WriteReport(path, r1); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Schema != reportSchema || back.Columns != 6 || back.Micro.F1 != r1.Micro.F1 {
		t.Errorf("round-trip разошёлся: schema=%s columns=%d micro=%v", back.Schema, back.Columns, back.Micro.F1)
	}
}

// TestReportText — сводка печатается без паники и содержит ключевые блоки.
func TestReportText(t *testing.T) {
	cols := testDataset()
	cfg := testConfig(nil)
	rr := runTest(t, cols, cfg)
	rep := BuildReport(&evalset.Manifest{Dataset: "1.0.0", Taxonomy: "1.0.0", Seed: 1}, cols, rr, cfg, []float64{0.8}, "test", "", "")
	var buf bytes.Buffer
	rep.Text(&buf)
	for _, want := range []string{"Eval-отчёт", "EMAIL", "micro:", "По видам", "Sweep", "Spoof-precision"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("сводка не содержит %q", want)
		}
	}
}
