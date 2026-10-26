// Тесты S9-3: пользовательский промпт на скан — разделение кэша по хэшу
// инструкции, provenance в scans, аудит старта (hash/length) и сверка resume.
package scanengine

import (
	"errors"
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy/prompts"
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// TestCacheKeySeparatesUserPrompts — одинаковые значения и scope, но разные
// пользовательские инструкции НЕ делят кэш; та же инструкция — попадает.
func TestCacheKeySeparatesUserPrompts(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = true
	cfg.CacheScope = testLLMID + "|" + testLLMModel
	cfg.UserPrompt = "контекст А"
	cfg.UserPromptHash = prompts.UserHash(cfg.UserPrompt)
	cfg.PromptBaseVersion = prompts.Version
	eng = New(st, eng.meta, cfg)
	llm := llmReasonAnswer()
	eng.SetLLM(llm, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep1, _ := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 || rep1.CacheHits != 0 {
		t.Fatalf("первый прогон: calls=%d hits=%d", llm.classifyCalls, rep1.CacheHits)
	}
	// тот же промпт → кэш обслуживает второй прогон
	rep2, _ := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 || rep2.CacheHits != 1 {
		t.Fatalf("тот же промпт должен попадать в кэш: calls=%d hits=%d", llm.classifyCalls, rep2.CacheHits)
	}
	// другой промпт → другой ключ, сетевой вызов повторяется
	cfg2 := cfg
	cfg2.UserPrompt = "контекст Б"
	cfg2.UserPromptHash = prompts.UserHash(cfg2.UserPrompt)
	eng2 := New(st, eng.meta, cfg2)
	llm2 := llmReasonAnswer()
	eng2.SetLLM(llm2, LLMIdentity{AgentID: testLLMID, Model: testLLMModel})
	rep3, _ := scanAndList(t, eng2, st, grayPhoneSource())
	if llm2.classifyCalls != 1 || rep3.CacheHits != 0 {
		t.Fatalf("другой промпт не должен делить кэш: calls=%d hits=%d", llm2.classifyCalls, rep3.CacheHits)
	}
}

// TestScanProvenanceUserPrompt — scans хранит версию базового промпта, хэш,
// исходный текст и факт включения LLM.
func TestScanProvenanceUserPrompt(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.UserPrompt = "это медицинская БД"
	cfg.UserPromptHash = prompts.UserHash(cfg.UserPrompt)
	cfg.PromptBaseVersion = prompts.Version
	eng = New(st, eng.meta, cfg)
	eng.SetLLM(llmReasonAnswer(), LLMIdentity{AgentID: testLLMID, Model: testLLMModel})

	rep, _ := scanAndList(t, eng, st, testSource())
	sc, err := st.GetScan(t.Context(), rep.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	if sc.PromptBaseVersion != prompts.Version || sc.PromptHash != cfg.UserPromptHash ||
		sc.PromptText != "это медицинская БД" || !sc.LLMEnabled {
		t.Fatalf("provenance промпта искажён: %+v", sc)
	}

	// без LLM и без промпта — честные пустые значения
	eng2, st2 := testEngine(t)
	rep2, _ := scanAndList(t, eng2, st2, testSource())
	sc2, err := st2.GetScan(t.Context(), rep2.ScanID)
	if err != nil {
		t.Fatal(err)
	}
	if sc2.PromptHash != "" || sc2.PromptText != "" || sc2.LLMEnabled {
		t.Fatalf("пустой provenance искажён: %+v", sc2)
	}
}

// TestScanStartAuditPromptDetails — аудит старта фиксирует hash/длину промпта
// и факт LLM, но не полный текст (S9-3, п. 14.2).
func TestScanStartAuditPromptDetails(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.UserPrompt = "медицинские данные"
	cfg.UserPromptHash = prompts.UserHash(cfg.UserPrompt)
	cfg.PromptBaseVersion = prompts.Version
	eng = New(st, eng.meta, cfg)

	rep, _ := scanAndList(t, eng, st, testSource())
	entries, err := st.AuditList(t.Context(), audit.Filter{ScanID: rep.ScanID})
	if err != nil {
		t.Fatal(err)
	}
	var start *audit.Entry
	for i := range entries {
		if entries[i].Action == "scan_start" {
			start = &entries[i]
		}
	}
	if start == nil {
		t.Fatal("scan_start не записан")
	}
	if start.Details["prompt_hash"] != cfg.UserPromptHash {
		t.Fatalf("prompt_hash в аудите: %+v", start.Details)
	}
	if start.Details["prompt_len"] != float64(len([]rune("медицинские данные"))) {
		t.Fatalf("prompt_len в аудите: %+v", start.Details)
	}
	if start.Details["llm"] != false {
		t.Fatalf("llm-флаг в аудите: %+v", start.Details)
	}
	if _, leaks := start.Details["prompt_text"]; leaks {
		t.Fatal("полный текст промпта в аудит не пишется")
	}
}

// TestValidateResumePromptFields — сверка prompt_base_version и prompt_hash;
// пустые значения legacy-прогона несовместимы (fail-closed).
func TestValidateResumePromptFields(t *testing.T) {
	base := store.Scan{
		ID: "s", SourceName: "db", Status: "partial",
		ConfigFingerprint: "f", TaxonomyVersion: "1", DetectorsVersion: "1", BinaryVersion: "dev",
		PromptBaseVersion: prompts.Version, PromptHash: "abc",
	}
	cfg := Config{
		ConfigFingerprint: "f", TaxonomyVersion: "1", DetectorsVersion: "1", BinaryVersion: "dev",
		UserPromptHash: "abc", PromptBaseVersion: prompts.Version,
	}
	if err := ValidateResume(&base, cfg); err != nil {
		t.Fatalf("совпавший provenance отклонён: %v", err)
	}

	// версия базового промпта отличается
	old := base
	old.PromptBaseVersion = "1"
	err := ValidateResume(&old, cfg)
	var compat *ResumeCompatibilityError
	if !errors.As(err, &compat) || len(compat.Mismatches) != 1 || compat.Mismatches[0].Field != "prompt_base_version" {
		t.Fatalf("mismatch prompt_base_version: %v", err)
	}

	// хэш инструкции отличается
	otherHash := base
	otherHash.PromptBaseVersion = prompts.Version
	otherHash.PromptHash = "другой"
	err = ValidateResume(&otherHash, cfg)
	if !errors.As(err, &compat) || len(compat.Mismatches) != 1 || compat.Mismatches[0].Field != "prompt_hash" {
		t.Fatalf("mismatch prompt_hash: %v", err)
	}

	// legacy-прогон без provenance промпта — несовместим, а не разрешение
	legacy := store.Scan{
		ID: "legacy", SourceName: "db", Status: "partial",
		ConfigFingerprint: "f", TaxonomyVersion: "1", DetectorsVersion: "1", BinaryVersion: "dev",
	}
	err = ValidateResume(&legacy, cfg)
	if !errors.As(err, &compat) {
		t.Fatalf("legacy-прогон должен быть несовместим: %v", err)
	}
	var fields []string
	for _, m := range compat.Mismatches {
		fields = append(fields, m.Field)
	}
	if !containsStr(fields, "prompt_base_version") || !containsStr(fields, "prompt_hash") {
		t.Fatalf("legacy mismatch'и: %v", fields)
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
