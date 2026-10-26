package scanengine

import (
	"context"
	"errors"
	"iter"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// fakeConnector — in-memory источник для E2E-теста движка (без сети/БД).
type fakeConnector struct {
	tables map[string][]connector.Column
	data   map[string][]connector.Row
	errs   map[string]error // имитация ошибок: "schema:<table>" | "sample:<table>"
	// errCount — сколько раз ошибка отдаётся до самоисцеления (retry-тесты,
	// инкремент 8): по исчерпании счётчика таблица работает штатно.
	errCount map[string]int
	calls    map[string]int // учёт вызовов (проверка пропуска при resume)
}

func (f *fakeConnector) popErr(key string) error {
	if n := f.errCount[key]; n > 0 {
		err := f.errs[key]
		if n == 1 {
			// самоисцеление: счётчик исчерпан — статическая ошибка больше не действует
			delete(f.errCount, key)
			delete(f.errs, key)
		} else {
			f.errCount[key] = n - 1
		}
		return err
	}
	return nil
}

func (f *fakeConnector) Ping(ctx context.Context) error { return nil }

func (f *fakeConnector) ListTables(ctx context.Context) ([]connector.TableRef, error) {
	out := make([]connector.TableRef, 0, len(f.tables))
	for name := range f.tables {
		out = append(out, connector.TableRef{Schema: "public", Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *fakeConnector) GetSchema(ctx context.Context, t connector.TableRef) ([]connector.Column, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	key := "schema:" + t.Name
	f.calls[key]++
	if err := f.popErr(key); err != nil {
		return nil, err
	}
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	return f.tables[t.Name], nil
}

func (f *fakeConnector) CountRows(ctx context.Context, t connector.TableRef) (int64, error) {
	return int64(len(f.data[t.Name])), nil
}

func (f *fakeConnector) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	key := "sample:" + spec.Table.Name
	f.calls[key]++
	if err := f.popErr(key); err != nil {
		return nil, err
	}
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	rows := f.data[spec.Table.Name]
	col := spec.Columns[0]
	return func(yield func(connector.Row, error) bool) {
		n := int64(0)
		for _, r := range rows {
			row := connector.Row{}
			if v, ok := r[col]; ok {
				row[col] = v
			}
			if !yield(row, nil) {
				return
			}
			n++
			if spec.MaxRows > 0 && n >= spec.MaxRows {
				return
			}
		}
	}, nil
}

func (f *fakeConnector) Close() error { return nil }

// validINN10 — ИНН с корректной контрольной суммой (7707083893).
const validINN10 = "7707083893"

func testEngine(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	m := meta.New(map[string][]string{
		"EMAIL":  {"email", "почта"},
		"TAX_ID": {"inn", "инн"},
	})
	cfg := Config{
		TauAccept:        0.80,
		SampleMode:       connector.SampleRows,
		SampleValue:      100,
		MaxRows:          1000,
		MaxStringChars:   200,
		Dedup:            true,
		TaxonomyVersion:  "1.0.0",
		DetectorsVersion: "1",
		Sensitivity: map[verdict.Label]verdict.Sensitivity{
			"EMAIL":       verdict.SensitivityPII,
			"PHONE":       verdict.SensitivityPII,
			"TAX_ID":      verdict.SensitivityPII,
			"CARD_NUMBER": verdict.SensitivityPCI,
			"UNKNOWN":     verdict.SensitivityNone,
		},
	}
	return New(st, m, cfg), st
}

func testSource() *fakeConnector {
	rows := []connector.Row{
		{"email": "ivan@example.com", "phone": "+7 999 123-45-67", "inn": validINN10, "created_at": "2026-01-01T00:00:00Z", "amount": "100"},
		{"email": "petr@test.io", "phone": "89991234568", "inn": "5001007321", "created_at": "2026-01-02T00:00:00Z", "amount": "200"},
		{"email": "anna@mail.ru", "phone": "9991234569", "inn": nil, "created_at": nil, "amount": "300"},
	}
	return &fakeConnector{
		tables: map[string][]connector.Column{
			"users": {
				{Name: "email", NativeType: "String", Ordinal: 0},
				{Name: "phone", NativeType: "String", Ordinal: 1},
				{Name: "inn", NativeType: "String", Ordinal: 2},
				{Name: "created_at", NativeType: "DateTime", Ordinal: 3},
				{Name: "amount", NativeType: "Int64", Ordinal: 4},
			},
			"cards": {
				{Name: "pan", NativeType: "String", Ordinal: 0},
			},
		},
		data: map[string][]connector.Row{
			"users": rows,
			"cards": {
				{"pan": "4111111111111111"},
				{"pan": "4242424242424242"},
				{"pan": nil},
			},
		},
	}
}

func scanAndList(t *testing.T, eng *Engine, st *store.Store, conn *fakeConnector) (*Report, map[string]verdict.Verdict) {
	t.Helper()
	ctx := context.Background()
	rep, err := eng.Scan(ctx, conn, "fake", "deep")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	vs, err := st.ListVerdicts(ctx, rep.ScanID)
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	byPath := map[string]verdict.Verdict{}
	for _, v := range vs {
		byPath[v.Table+"/"+v.Path] = v
	}
	return rep, byPath
}

func TestEndToEndScan(t *testing.T) {
	eng, st := testEngine(t)
	rep, vs := scanAndList(t, eng, st, testSource())

	if rep.Status != "done" || rep.TablesTotal != 2 || rep.TablesDone != 2 || rep.TablesFailed != 0 {
		t.Fatalf("отчёт: %+v", rep)
	}
	if rep.Verdicts != 6 || rep.Pending == 0 {
		t.Fatalf("ожидалось 6 вердиктов, %+v", rep)
	}

	cases := []struct {
		path   string
		label  verdict.Label
		status verdict.ReviewStatus
		layer  verdict.EvidenceLayer
	}{
		{"public.users/email", "EMAIL", verdict.StatusAutoAccepted, verdict.LayerEnsemble},
		// phone: 2 валидных из 3 (доля 0.667 → conf 0.70 < tau 0.80) — серая зона;
		// без LLM (nil) → pending (п. 7 правило 4/5). С LLM — эскалация (тест ниже).
		{"public.users/phone", "PHONE", verdict.StatusPending, verdict.LayerEnsemble},
		{"public.users/inn", "TAX_ID", verdict.StatusAutoAccepted, verdict.LayerRules},
		{"public.users/created_at", "UNKNOWN", verdict.StatusPending, verdict.LayerEnsemble},
		{"public.users/amount", "UNKNOWN", verdict.StatusPending, verdict.LayerEnsemble},
		{"public.cards/pan", "CARD_NUMBER", verdict.StatusAutoAccepted, verdict.LayerRules},
	}
	for _, c := range cases {
		v, ok := vs[c.path]
		if !ok {
			t.Fatalf("вердикт отсутствует: %s", c.path)
		}
		if v.Label != c.label || v.ReviewStatus != c.status || v.EvidenceLayer != c.layer {
			t.Errorf("%s: label=%s status=%s layer=%s; ожидалось %s/%s/%s",
				c.path, v.Label, v.ReviewStatus, v.EvidenceLayer, c.label, c.status, c.layer)
		}
		if v.Sensitivity == "" {
			t.Errorf("%s: sensitivity не проставлена", c.path)
		}
		if v.ID == "" || v.SampleSize == 0 {
			t.Errorf("%s: id/sample_size не заполнены: %+v", c.path, v)
		}
		if v.TaxonomyVersion != "1.0.0" || v.DetectorsVersion != "1" {
			t.Errorf("%s: версии provenance не проставлены", c.path)
		}
	}

	// checksum-победа: ИНН со 100% матчем → 0.99 rules
	if v := vs["public.users/inn"]; v.Confidence != 0.99 {
		t.Errorf("ИНН: confidence=%v, ожидался 0.99 (checksum)", v.Confidence)
	}
	// PAN через Luhn → 0.99
	if v := vs["public.cards/pan"]; v.Confidence != 0.99 {
		t.Errorf("PAN: confidence=%v, ожидался 0.99", v.Confidence)
	}
	// evidence: правило п. 5.4 — без сырых значений, только статистика
	ev, _ := vs["public.users/email"].Evidence["rules"].(map[string]any)
	if ev["rules/email"] == nil {
		t.Errorf("evidence rules/email отсутствует: %+v", vs["public.users/email"].Evidence)
	}
	if stringInAnyMap(vs["public.users/email"].Evidence, "ivan@example.com") {
		t.Error("сырое значение попало в evidence — запрещено ADR-0010")
	}
}

// fakeLLMClassifier — fake LLM-слой для E2E-теста эскалации (без HTTP).
type fakeLLMClassifier struct {
	classifyResult *agentproxy.ClassifyResult
	classifyErr    error
	verifyResult   *agentproxy.VerifyResult
	verifyErr      error
	classifyCalls  int
	verifyCalls    int
}

func (f *fakeLLMClassifier) Classify(ctx context.Context, nativeType string, values []string) (*agentproxy.ClassifyResult, error) {
	f.classifyCalls++
	return f.classifyResult, f.classifyErr
}

func (f *fakeLLMClassifier) Verify(ctx context.Context, candidate, nativeType string, values []string) (*agentproxy.VerifyResult, error) {
	f.verifyCalls++
	return f.verifyResult, f.verifyErr
}

// TestGrayCorridorLLMEscalation — серый коридор phone (0.70 < tau) → LLM
// вызывается, эскалация в верификатор → auto_accepted (blueprint п. 7).
func TestGrayCorridorLLMEscalation(t *testing.T) {
	eng, st := testEngine(t)
	llm := &fakeLLMClassifier{
		classifyResult: &agentproxy.ClassifyResult{Label: "PHONE", Confidence: 0.65, Sensitivity: "PII", PromptVersion: "1", ReasonRU: "номера мобильных, маскированы"},
		verifyResult:   &agentproxy.VerifyResult{Verdict: "confirm", Label: "PHONE", Confidence: 0.85, ReasonRU: "согласен — маскированные остатки совпадают"},
	}
	eng.SetLLM(llm, LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})
	_, vs := scanAndList(t, eng, st, testSource())

	v := vs["public.users/phone"]
	if llm.classifyCalls == 0 {
		t.Error("LLM-классификатор не вызван в сером коридоре")
	}
	// S8-6: объяснения LLM и верификатора — в evidence вердикта.
	llmEv, ok := v.Evidence["llm"].(map[string]any)
	if !ok || llmEv["reason_ru"] != "номера мобильных, маскированы" || llmEv["model"] != "gpt-4o-mini" {
		t.Fatalf("evidence llm: %+v", v.Evidence["llm"])
	}
	verEv, ok := v.Evidence["llm_verify"].(map[string]any)
	if !ok || verEv["verdict"] != "confirm" || verEv["reason_ru"] != "согласен — маскированные остатки совпадают" {
		t.Fatalf("evidence llm_verify: %+v", v.Evidence["llm_verify"])
	}
	// после confirm верификатора: confidence+0.1, auto_accepted, слой llm
	if v.ReviewStatus != verdict.StatusAutoAccepted || v.Label != "PHONE" {
		t.Errorf("phone после эскалации: label=%s status=%s; ожидалось PHONE/auto_accepted", v.Label, v.ReviewStatus)
	}
	if v.PromptVersion != "1" {
		t.Errorf("prompt_version не проставлен: %+v", v)
	}
}

// TestLLMNotCalledForChecksum — checksum (ИНН 0.99) → LLM не вызывается (п. 7 правило 1).
func TestLLMNotCalledForChecksum(t *testing.T) {
	eng, st := testEngine(t)
	llm := &fakeLLMClassifier{
		classifyResult: &agentproxy.ClassifyResult{Label: "PHONE", Confidence: 0.65, PromptVersion: "1"},
		verifyResult:   &agentproxy.VerifyResult{Verdict: "confirm", Label: "PHONE", Confidence: 0.85},
	}
	eng.SetLLM(llm, LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})
	_, vs := scanAndList(t, eng, st, testSource())
	if v := vs["public.users/inn"]; v.Confidence != 0.99 || v.EvidenceLayer != verdict.LayerRules {
		t.Errorf("ИНН должен остаться checksum 0.99 rules: %+v", v)
	}
	// LLM мог вызваться для phone (серая зона), но не для checksum-колонок;
	// главное — checksum-вердикты не переопределены
}

func TestFailedTableDoesNotStopScan(t *testing.T) {
	eng, st := testEngine(t)
	conn := testSource()
	conn.errs = map[string]error{"schema:users": errors.New("нет прав")}
	rep, vs := scanAndList(t, eng, st, conn)

	if rep.Status != "partial" || rep.TablesTotal != 2 || rep.TablesDone != 1 || rep.TablesFailed != 1 {
		t.Fatalf("partial-статус не выставлен: %+v", rep)
	}
	if len(vs) != 1 {
		t.Fatalf("вердикты только по cards: %+v", vs)
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("ошибка таблицы не в отчёте: %+v", rep.Errors)
	}
}

func TestNullHeavyColumnIsSmallSample(t *testing.T) {
	eng, st := testEngine(t)
	conn := testSource()
	for i := 0; i < 60; i++ {
		conn.data["users"] = append(conn.data["users"], connector.Row{"created_at": nil})
	}
	_, vs := scanAndList(t, eng, st, conn)
	v := vs["public.users/created_at"]
	if v.ReviewStatus != verdict.StatusPending || v.Label != "UNKNOWN" {
		t.Fatalf("null>0.95 должен давать UNKNOWN+pending: %+v", v)
	}
	if v.Evidence["reason"] != "small_sample" {
		t.Fatalf("reason small_sample не записан: %+v", v.Evidence)
	}
}

func stringInAnyMap(m map[string]any, s string) bool {
	for _, v := range m {
		switch x := v.(type) {
		case string:
			if x == s {
				return true
			}
		case map[string]any:
			if stringInAnyMap(x, s) {
				return true
			}
		}
	}
	return false
}

func TestReportTextRenders(t *testing.T) {
	eng, st := testEngine(t)
	rep, _ := scanAndList(t, eng, st, testSource())
	var buf stringsBuilder
	rep.Text(&buf)
	if buf.Len() == 0 {
		t.Fatal("отчёт пуст")
	}
}

// stringsBuilder — минимальный io.Writer для проверки отчёта.
type stringsBuilder struct{ b []byte }

func (s *stringsBuilder) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}

func (s *stringsBuilder) Len() int { return len(s.b) }

// TestVerdictEvidenceExamples — маскированные примеры сэмпла в evidence
// (S8-6): значения идут в UI только в маскированном виде (ADR-0010).
func TestVerdictEvidenceExamples(t *testing.T) {
	eng, st := testEngine(t)
	_, vs := scanAndList(t, eng, st, testSource())

	v := vs["public.users/email"]
	sample, ok := v.Evidence["sample"].(map[string]any)
	if !ok {
		t.Fatalf("evidence sample отсутствует: %+v", v.Evidence)
	}
	ex, ok := sample["examples"].([]any)
	if !ok || len(ex) == 0 {
		t.Fatalf("examples пусты: %+v", sample)
	}
	first, _ := ex[0].(string)
	if strings.Contains(first, "ivan@example.com") || strings.Contains(first, "petr@test.io") {
		t.Fatalf("example без маски: %q", first)
	}
	if len(ex) > 3 {
		t.Fatalf("examples больше 3: %d", len(ex))
	}
	// rules-евиденс присутствует и читаемо
	rules, ok := v.Evidence["rules"].(map[string]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("rules отсутствуют: %+v", v.Evidence)
	}
	if _, ok := rules["rules/email"].(map[string]any); !ok {
		t.Fatalf("rules/email не найдено: %+v", rules)
	}
}
