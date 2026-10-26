// Тесты S9-2: llm_status вердикта и полный per-column LLM evidence —
// вызов (called), попадание в кэш (cache_hit, parity с промахом), ошибка
// (error) и отсутствие вызова (not_called). Поверх fake LLM и реального store.
package scanengine

import (
	"strings"
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// llmReasonAnswer — classify с объяснением и чувствительностью: для проверки
// parity evidence при попадании в кэш (S9-2).
func llmReasonAnswer() *fakeLLMClassifier {
	return &fakeLLMClassifier{
		classifyResult: &agentproxy.ClassifyResult{
			Label: "PERSON_NAME", Confidence: 0.92, Sensitivity: "PII",
			ReasonRU: "похоже на персональные имена", PromptVersion: "1",
		},
	}
}

// TestLLMStatusMiss — вызов классификатора и верификатора: llm_status=called,
// evidence["llm"]/["llm_verify"] содержат ответ агента и экономику, учётные
// записи размечены operation и answer-полями.
func TestLLMStatusMiss(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	eng = New(st, eng.meta, cfg)
	llm := llmWithVerify()
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, vs := scanAndList(t, eng, st, budgetSource())
	for _, path := range []string{"public.users/phone_a", "public.users/phone_b"} {
		v := vs[path]
		if v.LLMStatus != verdict.LLMStatusCalled {
			t.Fatalf("%s: llm_status=%q, ожидался called: %+v", path, v.LLMStatus, v)
		}
		ev, ok := v.Evidence["llm"].(map[string]any)
		if !ok {
			t.Fatalf("%s: evidence llm отсутствует: %+v", path, v.Evidence)
		}
		for _, k := range []string{"label", "confidence", "sensitivity", "reason_ru",
			"prompt_version", "tokens_in", "tokens_out", "cost_usd", "latency_ms", "agent", "model"} {
			if _, ok := ev[k]; !ok {
				t.Fatalf("%s: в evidence llm нет ключа %s: %+v", path, k, ev)
			}
		}
		if ev["label"] != "PHONE" || ev["agent"] != testLLMID || ev["model"] != testLLMModel {
			t.Fatalf("%s: ответ агента в evidence искажён: %+v", path, ev)
		}
		if ev["tokens_in"].(float64) != 1000 || ev["tokens_out"].(float64) != 100 {
			t.Fatalf("%s: токены в evidence искажены: %+v", path, ev)
		}
		vev, ok := v.Evidence["llm_verify"].(map[string]any)
		if !ok {
			t.Fatalf("%s: evidence llm_verify отсутствует: %+v", path, v.Evidence)
		}
		for _, k := range []string{"verdict", "label", "confidence", "reason_ru",
			"agent", "model", "prompt_version", "tokens_in", "tokens_out", "cost_usd", "latency_ms"} {
			if _, ok := vev[k]; !ok {
				t.Fatalf("%s: в evidence llm_verify нет ключа %s: %+v", path, k, vev)
			}
		}
		if vev["agent"] != testLLMID || vev["model"] != testLLMModel || vev["tokens_in"].(float64) != 500 {
			t.Fatalf("%s: верификатор в evidence искажён: %+v", path, vev)
		}
	}
	calls, err := st.ListAgentCalls(t.Context(), rep.ScanID)
	if err != nil || len(calls) != 4 {
		t.Fatalf("записей %d (err=%v), ожидалось 4 (2 classify + 2 verify)", len(calls), err)
	}
	for _, c := range calls {
		switch c.Operation {
		case store.CallOpClassify:
			if c.Status != "ok" || c.AnswerLabel != "PHONE" || c.AnswerConfidence != 0.95 || c.Cached {
				t.Fatalf("classify-запись искажена: %+v", c)
			}
		case store.CallOpVerify:
			if c.Status != "ok" || c.AnswerLabel != "PHONE" || c.AnswerConfidence != 0.9 {
				t.Fatalf("verify-запись искажена: %+v", c)
			}
		default:
			t.Fatalf("неизвестная операция вызова: %+v", c)
		}
		if c.PromptVersion != "1" || c.TokensIn <= 0 || c.LatencyMS < 0 {
			t.Fatalf("provenance вызова искажён: %+v", c)
		}
	}
}

// TestLLMStatusCacheHitParity — второй прогон тех же значений обслуживается из
// кэша: llm_status=cache_hit, prompt_version заполнен (дефект hit-ветки закрыт),
// evidence["llm"] идентичен промаху (reason_ru/sensitivity из кэша), учётная
// запись cache_hit с answer-полями.
func TestLLMStatusCacheHitParity(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = true
	cfg.CacheScope = testLLMID + "|" + testLLMModel
	eng = New(st, eng.meta, cfg)
	llm := llmReasonAnswer()
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	_, vs1 := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 {
		t.Fatalf("первый скан: classify=%d, ожидался 1", llm.classifyCalls)
	}
	first := vs1["public.backup/phone_backup"]
	if first.LLMStatus != verdict.LLMStatusCalled || first.PromptVersion != "1" {
		t.Fatalf("первый прогон: %+v", first)
	}
	fev, _ := first.Evidence["llm"].(map[string]any)
	if fev["reason_ru"] != "похоже на персональные имена" || fev["sensitivity"] != "PII" {
		t.Fatalf("evidence промаха искажён: %+v", fev)
	}

	rep2, vs2 := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 {
		t.Fatalf("второй скан должен попасть в кэш: classify=%d", llm.classifyCalls)
	}
	v := vs2["public.backup/phone_backup"]
	if v.LLMStatus != verdict.LLMStatusCacheHit {
		t.Fatalf("llm_status=%q, ожидался cache_hit: %+v", v.LLMStatus, v)
	}
	if v.PromptVersion != "1" {
		t.Fatalf("prompt_version при cache_hit не заполнен: %+v", v)
	}
	ev, ok := v.Evidence["llm"].(map[string]any)
	if !ok {
		t.Fatalf("evidence llm при cache_hit отсутствует: %+v", v.Evidence)
	}
	if ev["reason_ru"] != fev["reason_ru"] || ev["sensitivity"] != fev["sensitivity"] ||
		ev["label"] != fev["label"] || ev["confidence"] != fev["confidence"] {
		t.Fatalf("evidence cache_hit не эквивалентен промаху: hit=%+v miss=%+v", ev, fev)
	}
	if ev["tokens_in"].(float64) != 0 || ev["cost_usd"].(float64) != 0 {
		t.Fatalf("у cache_hit экономика должна быть нулевой: %+v", ev)
	}
	// член кластера — распространённый вердикт без LLM
	if m := vs2["public.users/contact_phone"]; m.LLMStatus != verdict.LLMStatusClusterPropagated {
		t.Fatalf("член кластера: llm_status=%q, ожидался cluster_propagated", m.LLMStatus)
	}
	calls, err := st.ListAgentCalls(t.Context(), rep2.ScanID)
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	// cache_hit (classify) + verify эскалации (кэш покрывает только Classify)
	var c *store.AgentCall
	for i := range calls {
		if calls[i].Status == "cache_hit" {
			c = &calls[i]
		}
	}
	if c == nil {
		t.Fatalf("cache_hit-запись не найдена: %+v", calls)
	}
	if c.Status != "cache_hit" || !c.Cached || c.Operation != store.CallOpClassify {
		t.Fatalf("cache_hit-запись искажена: %+v", c)
	}
	if c.AnswerLabel != "PERSON_NAME" || c.AnswerConfidence != 0.92 ||
		c.AnswerSensitivity != "PII" || c.ReasonRU != "похоже на персональные имена" {
		t.Fatalf("answer-поля cache_hit искажены: %+v", c)
	}
	if c.PromptVersion != "1" || c.TokensIn != 0 || c.CostUSD != 0 {
		t.Fatalf("provenance cache_hit искажён: %+v", c)
	}
}

// TestLLMStatusError — ошибка классификатора: llm_status=error, evidence["llm"]
// не пишется, учётная запись error с непустым (обрезанным) текстом ошибки.
func TestLLMStatusError(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = false
	eng = New(st, eng.meta, cfg)
	longErr := "agentproxy: HTTP 500: " + strings.Repeat("x", 400)
	llm := &fakeLLMClassifier{
		classifyErr:  agentError(longErr),
		verifyResult: &agentproxy.VerifyResult{Verdict: "confirm", Label: "PHONE", Confidence: 0.9},
	}
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, vs := scanAndList(t, eng, st, budgetSource())
	v := vs["public.users/phone_a"]
	if v.LLMStatus != verdict.LLMStatusError {
		t.Fatalf("llm_status=%q, ожидался error: %+v", v.LLMStatus, v)
	}
	if v.Evidence["llm"] != nil {
		t.Fatalf("при ошибке evidence llm не пишется: %+v", v.Evidence)
	}
	calls, err := st.ListAgentCalls(t.Context(), rep.ScanID)
	if err != nil {
		t.Fatalf("ListAgentCalls: %v", err)
	}
	var classifyErrs int
	for _, c := range calls {
		if c.Operation == store.CallOpClassify && c.Status == "error" {
			classifyErrs++
			if c.Error == "" {
				t.Fatalf("текст ошибки пуст: %+v", c)
			}
			if len([]rune(c.Error)) > 301 { // 300 символов + многоточие
				t.Fatalf("ошибка не обрезана: %d символов", len([]rune(c.Error)))
			}
			if c.AnswerLabel != "" || c.Cached || c.TokensIn != 0 {
				t.Fatalf("error-запись искажена: %+v", c)
			}
		}
	}
	if classifyErrs != 2 {
		t.Fatalf("error-записей classify %d, ожидалось 2: %+v", classifyErrs, calls)
	}
}

// agentError — ошибка с длинным текстом для проверки truncErr.
type agentError string

func (e agentError) Error() string { return string(e) }

// TestLLMStatusNotCalled — без LLM-слоя и уверенные rules-вердикты вызова нет:
// llm_status=not_called на всех колонках.
func TestLLMStatusNotCalled(t *testing.T) {
	eng, st := testEngine(t)
	_, vs := scanAndList(t, eng, st, testSource())
	for path, v := range vs {
		if v.LLMStatus != verdict.LLMStatusNotCalled {
			t.Fatalf("%s: llm_status=%q, ожидался not_called: %+v", path, v.LLMStatus, v)
		}
	}
	// с подключённым LLM checksum-правила (ИНН 0.99) тоже без вызова (п. 7 правило 1)
	eng2, st2 := testEngine(t)
	llm := llmWithVerify()
	eng2.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})
	_, vs2 := scanAndList(t, eng2, st2, testSource())
	if vs2["public.users/inn"].LLMStatus != verdict.LLMStatusNotCalled {
		t.Fatalf("checksum-колонка: %+v", vs2["public.users/inn"])
	}
}
