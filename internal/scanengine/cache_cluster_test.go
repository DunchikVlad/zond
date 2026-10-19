package scanengine

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/connector"
)

// grayPhoneSource — две таблицы с колонками ОДИНАКОВЫХ значений
// (2 телефона + 1 постороннее): правила дают 0.70 → серая зона (п. 7).
// Одинаковые значения → одинаковый отпечаток → один кластер (п. 7.6).
func grayPhoneSource() *fakeConnector {
	rowsA := []connector.Row{
		{"contact_phone": "+7 999 123-45-67"},
		{"contact_phone": "+7 999 123-45-68"},
		{"contact_phone": "not-a-phone-at-all"},
	}
	rowsB := []connector.Row{
		{"phone_backup": "+7 999 123-45-67"},
		{"phone_backup": "+7 999 123-45-68"},
		{"phone_backup": "not-a-phone-at-all"},
	}
	return &fakeConnector{
		tables: map[string][]connector.Column{
			"users":  {{Name: "contact_phone", NativeType: "String", Ordinal: 0}},
			"backup": {{Name: "phone_backup", NativeType: "String", Ordinal: 0}},
		},
		data: map[string][]connector.Row{"users": rowsA, "backup": rowsB},
	}
}

func llmWithAnswer() *fakeLLMClassifier {
	return &fakeLLMClassifier{
		classifyResult: &agentproxy.ClassifyResult{Label: "PERSON_NAME", Confidence: 0.92, PromptVersion: "1"},
	}
}

// TestClusterPropagation — представитель кластера классифицируется через LLM,
// член кластера (таблица backup) получает вердикт без LLM-вызова (п. 7.6).
func TestClusterPropagation(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = true
	eng = New(st, eng.meta, cfg)
	llm := llmWithAnswer()
	eng.SetLLM(llm, LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})

	rep, vs := scanAndList(t, eng, st, grayPhoneSource())
	if rep.ClusterPropagated != 1 {
		t.Fatalf("propagated=%d, ожидался 1: %+v", rep.ClusterPropagated, rep)
	}
	if llm.classifyCalls != 1 {
		t.Fatalf("LLM вызван %d раз, ожидался 1 (кластеризация)", llm.classifyCalls)
	}
	// ListTables сортирует: backup идёт первой → её phone_backup — представитель,
	// users/contact_phone — член кластера (п. 7.6: первый по порядку — представитель).
	repV, ok := vs["backup/phone_backup"]
	membV, ok2 := vs["users/contact_phone"]
	if !ok || !ok2 {
		t.Fatalf("вердикты отсутствуют: %v", vs)
	}
	if repV.ClusterID == "" || repV.ClusterID != membV.ClusterID {
		t.Fatalf("cluster_id должен совпадать: %q vs %q", repV.ClusterID, membV.ClusterID)
	}
	if membV.Label != repV.Label || membV.Confidence != repV.Confidence {
		t.Fatalf("вердикт члена не распространён: %+v vs %+v", membV, repV)
	}
	if membV.Evidence["cluster_propagated"] != true {
		t.Fatalf("cluster_propagated не записан: %+v", membV.Evidence)
	}
	if repV.Evidence["cluster_propagated"] != nil {
		t.Fatalf("представитель не должен иметь cluster_propagated: %+v", repV.Evidence)
	}
}

// TestVerdictCacheAcrossScans — повторный скан тех же значений обслуживается
// из кэша вердиктов без LLM-вызова (п. 10.5).
func TestVerdictCacheAcrossScans(t *testing.T) {
	eng, st := testEngine(t)
	cfg := eng.cfg
	cfg.Clustering = true
	cfg.CacheScope = "zond-main|gpt-4o-mini"
	eng = New(st, eng.meta, cfg)
	llm := llmWithAnswer()
	eng.SetLLM(llm, LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})

	rep1, _ := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 || rep1.CacheHits != 0 {
		t.Fatalf("первый скан: calls=%d hits=%d", llm.classifyCalls, rep1.CacheHits)
	}
	rep2, vs2 := scanAndList(t, eng, st, grayPhoneSource())
	if llm.classifyCalls != 1 {
		t.Fatalf("второй скан должен попасть в кэш: calls=%d", llm.classifyCalls)
	}
	if rep2.CacheHits != 1 {
		t.Fatalf("cacheHits=%d, ожидался 1: %+v", rep2.CacheHits, rep2)
	}
	v := vs2["backup/phone_backup"] // представитель — через него идёт кэш
	ev, _ := v.Evidence["llm_cache"].(map[string]any)
	if ev == nil || ev["hit"] != true {
		t.Fatalf("llm_cache.hit не записан: %+v", v.Evidence)
	}
}

// TestClusteringDisabledByDefault — без Clustering колонки не объединяются.
func TestClusteringDisabledByDefault(t *testing.T) {
	eng, st := testEngine(t)
	llm := llmWithAnswer()
	eng.SetLLM(llm, LLMIdentity{AgentID: "zond-main", Model: "gpt-4o-mini"})
	rep, vs := scanAndList(t, eng, st, grayPhoneSource())
	if rep.ClusterPropagated != 0 {
		t.Fatalf("propagated без Clustering: %+v", rep)
	}
	if vs["users/contact_phone"].ClusterID != "" || vs["backup/phone_backup"].ClusterID != "" {
		t.Fatalf("cluster_id без Clustering должен быть пуст")
	}
}
