// Тест инструментации движка счётчиками observe (п. 17): прогон с fake-LLM
// должен отразиться в Default-дельтах (expvar-источник /debug/vars).
package scanengine

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/observe"
)

// TestObserveInstrumentation — E2E-прогон (2 таблицы, 6 вердиктов, серый
// коридор phone → classify+verify) инкрементирует счётчики процесса.
// Тесты пакета последовательны (без t.Parallel) — дельты точные.
func TestObserveInstrumentation(t *testing.T) {
	before := observe.Default.Snapshot()

	eng, st := testEngine(t)
	llm := &fakeLLMClassifier{
		classifyResult: &agentproxy.ClassifyResult{Label: "PHONE", Confidence: 0.65,
			Sensitivity: "PII", PromptVersion: "1", Usage: agentproxy.Usage{TokensIn: 100, TokensOut: 20}},
		verifyResult: &agentproxy.VerifyResult{Verdict: "confirm", Label: "PHONE",
			Confidence: 0.85, Usage: agentproxy.Usage{TokensIn: 50, TokensOut: 10}},
	}
	eng.SetLLM(llm, LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})
	rep, _ := scanAndList(t, eng, st, testSource())
	if rep.Status != "done" {
		t.Fatalf("статус прогона %s, ожидался done", rep.Status)
	}

	after := observe.Default.Snapshot()
	if d := after.ScansStarted - before.ScansStarted; d != 1 {
		t.Errorf("scans_started дельта = %d, ожидалось 1", d)
	}
	if d := after.ScansFinished - before.ScansFinished; d != 1 {
		t.Errorf("scans_finished дельта = %d, ожидалось 1", d)
	}
	if d := after.ScansByStatus["done"] - before.ScansByStatus["done"]; d != 1 {
		t.Errorf("by_status[done] дельта = %d, ожидалось 1", d)
	}
	if d := after.LLMCalls - before.LLMCalls; d != 2 {
		t.Errorf("llm_calls дельта = %d, ожидалось 2 (classify + verify)", d)
	}
	if d := after.TokensIn - before.TokensIn; d != 150 || after.TokensOut-before.TokensOut != 30 {
		t.Errorf("tokens дельта = %d/%d, ожидалось 150/30",
			after.TokensIn-before.TokensIn, after.TokensOut-before.TokensOut)
	}
	if d := after.Verdicts - before.Verdicts; d != 6 {
		t.Errorf("verdicts дельта = %d, ожидалось 6", d)
	}
	if d := after.LLMCacheHits - before.LLMCacheHits; d != 0 {
		t.Errorf("cache_hits дельта = %d, ожидалось 0 (кэш выключен)", d)
	}
	if d := after.LLMErrors - before.LLMErrors; d != 0 {
		t.Errorf("llm_errors дельта = %d, ожидалось 0", d)
	}
}
