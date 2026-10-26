package scanengine

import (
	"errors"
	"math"
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/verdict"
)

// E2E-инкремента 4в: учёт вызовов в agent_calls (п. 10.6, атомарность п. 13),
// budget-стоп (п. 10.4) и ошибки LLM (запись status='error', скан не падает).
//
// Модель ансамбля в этих тестах: имена колонок вида phone_* матчат regex
// слоя 0 (`phone` → PHONE 0.60, п. 5.6), значения (2 телефона из 3) дают
// rules PHONE 0.70; ответ агента PHONE 0.95 сливается с ними:
// conf = (1.0·0.60 + 1.5·0.70 + 1.2·0.95)/3.7 = 0.7541 — в серой зоне
// [0.3, tauAccept] (grayBand движка по умолчанию) → каждая серая колонка
// идёт путь classify → эскалация verify (п. 7 правило 4). Подтверждение
// верификатора (confirm PHONE) → auto_accepted.

const testLLMID = "zond-main"
const testLLMModel = "gpt-4o-mini"

// budgetSource — одна таблица, две серые колонки (2 телефона из 3) с РАЗНЫМИ
// значениями: без кластеризации/кэша каждая колонка порождает свой вызов LLM.
func budgetSource() *fakeConnector {
	return &fakeConnector{
		tables: map[string][]connector.Column{
			"users": {
				{Name: "phone_a", NativeType: "String", Ordinal: 0},
				{Name: "phone_b", NativeType: "String", Ordinal: 1},
			},
		},
		data: map[string][]connector.Row{
			"users": {
				{"phone_a": "+7 999 123-45-67", "phone_b": "+7 900 555-01-01"},
				{"phone_a": "+7 999 123-45-68", "phone_b": "+7 900 555-01-02"},
				{"phone_a": "not-a-phone-at-all", "phone_b": "junk-junk-junk"},
			},
		},
	}
}

// llmWithVerify — fake с ответами классификатора (PHONE 0.95) и верификатора
// (confirm PHONE). Usage обоих фиксирован: classify 1000/100, verify 500/50.
func llmWithVerify() *fakeLLMClassifier {
	return &fakeLLMClassifier{
		classifyResult: &agentproxy.ClassifyResult{
			Label: "PHONE", Confidence: 0.95, PromptVersion: prompts.Version,
			Usage: agentproxy.Usage{TokensIn: 1000, TokensOut: 100},
		},
		verifyResult: &agentproxy.VerifyResult{
			Verdict: "confirm", Label: "PHONE", Confidence: 0.9,
			Usage: agentproxy.Usage{TokensIn: 500, TokensOut: 50},
		},
	}
}

func nearlyEq(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestAgentCallsRecorded — вызовы LLM пишутся в agent_calls той же транзакцией,
// что и вердикты (п. 13): classify (1) + попадание в кэш (1) + верификаторы
// (2, по одному на колонку) = 4 записи; записи связаны с вердиктами,
// экономика (токены, стоимость) заполнена по прайс-листу model_prices.
func TestAgentCallsRecorded(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	cfg.CacheScope = testLLMID + "|" + testLLMModel // кэш включён (п. 10.5)
	eng = New(st, eng.meta, cfg)
	llm := llmWithVerify()
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	// Две таблицы с ОДИНАКОВЫМИ значениями: второй скан колонки — попадание
	// в кэш (тот же отпечаток значений → тот же ключ), но верификатор
	// вызывается для обеих колонок (кэш покрывает только Classify, п. 10.5).
	rep, _ := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 || llm.verifyCalls != 2 {
		t.Fatalf("calls=%d verify=%d, ожидалось 1/2", llm.classifyCalls, llm.verifyCalls)
	}
	if rep.LLMCalls != 1 || rep.CacheHits != 1 {
		t.Fatalf("rep: llm=%d cache=%d, ожидалось 1/1: %+v", rep.LLMCalls, rep.CacheHits, rep)
	}
	// Токены: classify 1000/100 + два verify по 500/50 (кэш — без токенов).
	if rep.TokensIn != 2000 || rep.TokensOut != 200 {
		t.Fatalf("итоги токенов: %d/%d, ожидалось 2000/200", rep.TokensIn, rep.TokensOut)
	}
	// cost = (1000·0.15 + 100·0.60 + 2·(500·0.15 + 50·0.60))/1e6 (прайс gpt-4o-mini)
	if !nearlyEq(rep.CostUSD, 0.00042) {
		t.Fatalf("CostUSD=%v, ожидался 0.00042", rep.CostUSD)
	}

	calls, err := st.ListAgentCalls(t.Context(), rep.ScanID)
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	if want := rep.LLMCalls + rep.CacheHits + llm.verifyCalls; len(calls) != want {
		t.Fatalf("записей %d, ожидалось llm(%d)+cache(%d)+verify(%d)=%d",
			len(calls), rep.LLMCalls, rep.CacheHits, llm.verifyCalls, want)
	}
	vs, err := st.ListVerdicts(t.Context(), rep.ScanID)
	if err != nil {
		t.Fatalf("ListVerdicts: %v", err)
	}
	verdictIDs := map[string]bool{}
	for _, v := range vs {
		verdictIDs[v.ID] = true
	}
	var nOK, nCache int
	for _, c := range calls {
		if !verdictIDs[c.VerdictID] {
			t.Fatalf("вызов %s ссылается на несуществующий вердикт %s", c.ID, c.VerdictID)
		}
		if c.ScanID != rep.ScanID || c.AgentID != testLLMID || c.Model != testLLMModel {
			t.Fatalf("идентичность вызова искажена: %+v", c)
		}
		if c.PromptVersion != prompts.Version || c.CreatedAt.IsZero() || c.ID == "" {
			t.Fatalf("provenance вызова не заполнен: %+v", c)
		}
		switch c.Status {
		case "ok": // classify или verify: токены и стоимость по прайсу
			nOK++
			if c.Cached || c.TokensIn <= 0 || c.TokensOut <= 0 || c.CostUSD <= 0 {
				t.Fatalf("ok-запись искажена: %+v", c)
			}
		case "cache_hit": // сетевого вызова нет — токены/стоимость нулевые
			nCache++
			if !c.Cached || c.TokensIn != 0 || c.TokensOut != 0 || c.CostUSD != 0 {
				t.Fatalf("cache_hit-запись искажена: %+v", c)
			}
		default:
			t.Fatalf("неожиданный статус вызова: %+v", c)
		}
	}
	if nOK != 3 || nCache != 1 {
		t.Fatalf("должно быть 3 ok (classify + 2 verify) и 1 cache_hit: %+v", calls)
	}
}

// TestBudgetExceededStopsLLM — cost_scan_limit_usd ниже стоимости первого
// вызова: после него LLM прекращается (п. 10.4), вторая серая колонка без
// вызова → pending с budget_exceeded в evidence, скан — budget_exceeded.
func TestBudgetExceededStopsLLM(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	cfg.CostScanLimitUSD = 0.10
	eng = New(st, eng.meta, cfg)
	llm := &fakeLLMClassifier{
		// 1M входящих токенов × 0.15/1M = 0.15 >= 0.10 → budget-стоп
		classifyResult: &agentproxy.ClassifyResult{
			Label: "PHONE", Confidence: 0.65, PromptVersion: prompts.Version,
			Usage: agentproxy.Usage{TokensIn: 1_000_000},
		},
		verifyResult: &agentproxy.VerifyResult{Verdict: "confirm", Label: "PHONE", Confidence: 0.9},
	}
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, vs := scanAndList(t, eng, st, budgetSource())
	if rep.Status != "budget_exceeded" {
		t.Fatalf("статус скана: %q, ожидался budget_exceeded: %+v", rep.Status, rep)
	}
	if llm.classifyCalls != 1 {
		t.Fatalf("LLM вызван %d раз, ожидался 1 (budget-стоп)", llm.classifyCalls)
	}
	if llm.verifyCalls != 0 {
		t.Fatalf("верификатор вызван %d раз при превышенном бюджете", llm.verifyCalls)
	}
	first := vs["public.users/phone_a"] // обрабатывается первой → вызов успел сделаться
	second := vs["public.users/phone_b"]
	if first.Evidence["budget_exceeded"] == true {
		t.Fatalf("первая колонка до бюджета, пометки быть не должно: %+v", first.Evidence)
	}
	if second.ReviewStatus != verdict.StatusPending {
		t.Fatalf("вторая колонка без LLM должна остаться pending: %+v", second)
	}
	if second.Evidence["budget_exceeded"] != true {
		t.Fatalf("в evidence второй колонки должен быть budget_exceeded: %+v", second.Evidence)
	}
	if first.LLMStatus != verdict.LLMStatusCalled {
		t.Fatalf("первая колонка: llm_status=%q, ожидался called", first.LLMStatus)
	}
	if second.LLMStatus != verdict.LLMStatusBudgetExceeded {
		t.Fatalf("вторая колонка: llm_status=%q, ожидался budget_exceeded", second.LLMStatus)
	}
	if !nearlyEq(rep.CostUSD, 0.15) {
		t.Fatalf("CostUSD=%v, ожидался 0.15", rep.CostUSD)
	}
	calls, err := st.ListAgentCalls(t.Context(), rep.ScanID)
	if err != nil || len(calls) != 1 {
		t.Fatalf("записей вызовов %d (err=%v), ожидалась 1", len(calls), err)
	}
	if calls[0].Status != "ok" || calls[0].VerdictID != first.ID {
		t.Fatalf("запись первого вызова искажена: %+v", calls[0])
	}
}

// TestBudgetNotExceededBelowLimit — лимит выше фактической стоимости: скан
// завершается обычным статусом; каждая серая колонка порождает classify +
// верификатора (п. 7 правило 4): 2 колонки × 2 вызова = 4 записи.
func TestBudgetNotExceededBelowLimit(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	cfg.CostScanLimitUSD = 1.0
	eng = New(st, eng.meta, cfg)
	llm := llmWithVerify()
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, vs := scanAndList(t, eng, st, budgetSource())
	if rep.Status != "done" {
		t.Fatalf("статус скана: %q, ожидался done", rep.Status)
	}
	if llm.classifyCalls != 2 || llm.verifyCalls != 2 {
		t.Fatalf("classify=%d verify=%d, ожидалось 2/2 (бюджет не исчерпан)", llm.classifyCalls, llm.verifyCalls)
	}
	if vs["public.users/phone_b"].Evidence["budget_exceeded"] != nil {
		t.Fatalf("budget_exceeded без причины: %+v", vs["public.users/phone_b"].Evidence)
	}
	calls, _ := st.ListAgentCalls(t.Context(), rep.ScanID)
	if len(calls) != 4 {
		t.Fatalf("записей вызовов %d, ожидалось 4", len(calls))
	}
}

// TestLLMErrorRecorded — ошибки классификатора и верификатора: записи
// status='error' (usage/cost 0), вердикт без LLM-кандидата, скан не падает.
// Обе серые колонки проходят путь classify→verify: 2 колонки × 2 ошибки = 4.
func TestLLMErrorRecorded(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	eng = New(st, eng.meta, cfg)
	llm := &fakeLLMClassifier{
		classifyErr: errors.New("agentproxy: HTTP 500: boom"),
		verifyErr:   errors.New("agentproxy: HTTP 500: boom"),
	}
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, vs := scanAndList(t, eng, st, budgetSource())
	if rep.Status != "done" {
		t.Fatalf("скан с ошибками LLM не должен падать: %+v", rep)
	}
	if rep.LLMErrors != 4 {
		t.Fatalf("LLMErrors=%d, ожидалось 4 (2 колонки × classify+verify)", rep.LLMErrors)
	}
	if rep.LLMCalls != 0 || rep.CostUSD != 0 {
		t.Fatalf("ошибки не должны давать вызовы/стоимость: %+v", rep)
	}
	v := vs["public.users/phone_a"]
	if v.ReviewStatus != verdict.StatusPending || v.EvidenceLayer == verdict.LayerLLM {
		t.Fatalf("вердикт без LLM-кандидата: %+v", v)
	}
	if v.LLMStatus != verdict.LLMStatusError { // S9-2
		t.Fatalf("llm_status=%q, ожидался error: %+v", v.LLMStatus, v)
	}
	calls, err := st.ListAgentCalls(t.Context(), rep.ScanID)
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	if len(calls) != 4 {
		t.Fatalf("записей ошибок %d, ожидалось 4: %+v", len(calls), calls)
	}
	verdictIDs := map[string]bool{v.ID: true, vs["public.users/phone_b"].ID: true}
	for _, c := range calls {
		if c.Status != "error" || c.Cached {
			t.Fatalf("запись ошибки искажена: %+v", c)
		}
		if c.TokensIn != 0 || c.TokensOut != 0 || c.CostUSD != 0 {
			t.Fatalf("у ошибки usage/cost должны быть 0: %+v", c)
		}
		if !verdictIDs[c.VerdictID] {
			t.Fatalf("запись ошибки ссылается на чужой вердикт: %+v", c)
		}
	}
}

// TestAgentCallsCommitPerTable — вызовы коммитятся вместе с вердиктами таблицы
// (атомарность п. 13): failed-таблица не оставляет записей, попадающих в
// коммит соседней таблицы. backup порождает classify + verify (п. 7) = 2
// записи, обе — на вердикт backup.
func TestAgentCallsCommitPerTable(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	eng = New(st, eng.meta, cfg)
	llm := llmWithVerify()
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	conn := grayPhoneSource()
	conn.errs = map[string]error{"schema:users": errors.New("нет прав")} // users первая → failed
	rep, vs := scanAndList(t, eng, st, conn)
	if rep.TablesFailed != 1 {
		t.Fatalf("failed-таблица не зафиксирована: %+v", rep)
	}
	// failed-таблица не порождала вызовов (обрыв до классификации); важно, что
	// буфер failed-таблицы не протёк в коммит backup.
	calls, err := st.ListAgentCalls(t.Context(), rep.ScanID)
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	backupVerdict := vs["public.backup/phone_backup"].ID
	if len(calls) != 2 {
		t.Fatalf("записей %d, ожидалось 2 (classify + verify backup): %+v", len(calls), calls)
	}
	for _, c := range calls {
		if c.VerdictID != backupVerdict {
			t.Fatalf("вызов чужого вердикта (утечка буфера failed-таблицы?): %+v", c)
		}
	}
}
