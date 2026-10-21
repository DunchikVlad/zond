// Тесты счётчиков процесса (blueprint п. 17).
package observe

import (
	"bytes"
	"encoding/json"
	"expvar"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMeterSnapshot(t *testing.T) {
	m := NewMeter()
	m.IncrScanStarted()
	m.IncrScanFinished("done")
	m.IncrScanFinished("done")
	m.IncrScanFinished("budget_exceeded")
	m.IncrLLMCall()
	m.IncrLLMCall()
	m.IncrLLMError()
	m.IncrCacheHit()
	m.IncrClusterPropagated()
	m.AddTokens(150, 30)
	m.AddCostUSD(0.0006)
	m.AddVerdicts(42)

	snap := m.Snapshot()
	if snap.ScansStarted != 1 || snap.ScansFinished != 3 {
		t.Errorf("scans started/finished = %d/%d, ожидалось 1/3", snap.ScansStarted, snap.ScansFinished)
	}
	if snap.ScansByStatus["done"] != 2 || snap.ScansByStatus["budget_exceeded"] != 1 || len(snap.ScansByStatus) != 2 {
		t.Errorf("by_status = %v, ожидалось {done:2 budget_exceeded:1}", snap.ScansByStatus)
	}
	if snap.LLMCalls != 2 || snap.LLMErrors != 1 || snap.LLMCacheHits != 1 || snap.ClusterPropagated != 1 {
		t.Errorf("llm calls/errors/cache/cluster = %d/%d/%d/%d", snap.LLMCalls, snap.LLMErrors, snap.LLMCacheHits, snap.ClusterPropagated)
	}
	if snap.TokensIn != 150 || snap.TokensOut != 30 || snap.CostUSD != 0.0006 {
		t.Errorf("tokens/cost = %d/%d/%v, ожидалось 150/30/0.0006", snap.TokensIn, snap.TokensOut, snap.CostUSD)
	}
	if snap.Verdicts != 42 {
		t.Errorf("verdicts = %d, ожидалось 42", snap.Verdicts)
	}
}

func TestMeterJSONRoundTrip(t *testing.T) {
	m := NewMeter()
	m.IncrScanFinished("partial")
	m.AddCostUSD(1.25)
	var back Metrics
	if err := json.Unmarshal([]byte(m.String()), &back); err != nil {
		t.Fatalf("String() не валиден как JSON: %v", err)
	}
	if back.ScansByStatus["partial"] != 1 || back.CostUSD != 1.25 {
		t.Errorf("round-trip: %+v", back)
	}
}

// TestPublishExpvarIdempotent — повторная публикация не паникует (глобальный
// реестр expvar), а /debug/vars отдаёт zond/process.
func TestPublishExpvarIdempotent(t *testing.T) {
	PublishExpvar()
	PublishExpvar()
	req := httptest.NewRequest("GET", "/debug/vars", nil)
	rec := httptest.NewRecorder()
	expvar.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expvar handler: %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"zond/process"`)) {
		t.Error("/debug/vars не содержит zond/process")
	}
	if !strings.Contains(rec.Body.String(), `"scans_finished"`) {
		t.Error("снимок zond/process без ожидаемых полей")
	}
}
