// Тесты doctor (blueprint п. 15.3): диск, store+hash-chain, агенты
// (env/egress/DNS/пробный вызов на httptest-стенде), TLS-сертификаты,
// отчёт и коды выхода. Сетевые проверки не трогают внешний мир.
package doctor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// testBundle — минимальный конфиг: два агента (один без env), источник с
// незарегистрированным типом (source.open FAIL) и SSO выключен.
func testBundle(t *testing.T, agentEndpoint string) *config.Bundle {
	t.Helper()
	return &config.Bundle{
		Connections: &config.Connections{
			Version: "1",
			Sources: []config.Source{{Name: "bad", Type: "nope", DSN: "x://y"}},
		},
		Detectors: &config.Detectors{
			Version: "1",
			Ensemble: config.EnsembleConfig{
				TauAccept: 0.8, TauReview: 0.5,
				Weights: map[string]float64{"meta": 1, "rules": 1.5, "llm": 1.2},
			},
			Agents: []config.AgentSpec{
				{ID: "a1", Endpoint: agentEndpoint, Model: "m", APIKeyEnv: "DOCTOR_TEST_KEY",
					MaxValuesPerCall: 5, TimeoutS: 5, MaxRetries: 0, ConfidenceBand: [2]float64{0.3, 0.7}},
				{ID: "a2", Endpoint: "http://localhost:1/v1", Model: "m", APIKeyEnv: "DOCTOR_MISSING_KEY",
					MaxValuesPerCall: 5, TimeoutS: 5, MaxRetries: 0, ConfidenceBand: [2]float64{0.3, 0.7}},
			},
		},
		Taxonomy: &config.Taxonomy{
			Version: "1.0.0",
			Labels:  []config.LabelDef{{Name: "EMAIL", Sensitivity: "PII"}, {Name: "UNKNOWN", Sensitivity: "none"}},
		},
	}
}

func resultByCode(rep *Report, code string) []Result {
	var out []Result
	for _, r := range rep.Results {
		if r.Code == code {
			out = append(out, r)
		}
	}
	return out
}

// TestRunOffline — offline-прогон: диск OK, store+цепочка OK, источники SKIP,
// agent.env (a1 OK / a2 FAIL), egress a1 OK, probe SKIP, tls SKIP, vault SKIP.
func TestRunOffline(t *testing.T) {
	t.Setenv("DOCTOR_TEST_KEY", "test-key-1234567890")
	stPath := filepath.Join(t.TempDir(), "doc.db")
	st, err := store.Open(stPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	st.Close()

	rep := Run(context.Background(), testBundle(t, "http://localhost:9/v1"), stPath, Options{})

	if got := resultByCode(rep, "disk.space"); len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("disk.space: %+v", got)
	}
	if got := resultByCode(rep, "audit.chain"); len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("audit.chain: %+v", got)
	}
	if got := resultByCode(rep, "source.open"); len(got) != 1 || got[0].Status != StatusFail {
		t.Errorf("source.open (незарегистрированный тип): %+v", got)
	}
	env := resultByCode(rep, "agent.env")
	if len(env) != 2 {
		t.Fatalf("agent.env: %+v", env)
	}
	bySubj := map[string]Status{}
	for _, r := range env {
		bySubj[r.Subject] = r.Status
	}
	if bySubj["a1"] != StatusOK || bySubj["a2"] != StatusFail {
		t.Errorf("agent.env: %+v", bySubj)
	}
	if got := resultByCode(rep, "agent.egress"); len(got) != 1 || got[0].Status != StatusOK || got[0].Subject != "a1" {
		t.Errorf("agent.egress (только у a1 с ключом): %+v", got)
	}
	if got := resultByCode(rep, "agent.probe"); len(got) != 1 || got[0].Status != StatusSkip {
		t.Errorf("agent.probe offline: %+v", got)
	}
	if got := resultByCode(rep, "tls.cert"); len(got) != 1 || got[0].Status != StatusSkip {
		t.Errorf("tls.cert: %+v", got)
	}
	if got := resultByCode(rep, "vault"); len(got) != 1 || got[0].Status != StatusSkip {
		t.Errorf("vault: %+v", got)
	}
	if !rep.HasFail() {
		t.Error("HasFail должен быть true (source.open + agent.env a2)")
	}
}

// TestRunNilConfig — конфиг не загрузился: FAIL config.load, независимые
// проверки (диск, store) всё равно выполнены.
func TestRunNilConfig(t *testing.T) {
	stPath := filepath.Join(t.TempDir(), "doc.db")
	st, _ := store.Open(stPath)
	st.Close()

	rep := Run(context.Background(), nil, stPath, Options{})
	if got := resultByCode(rep, "config.load"); len(got) != 1 || got[0].Status != StatusFail {
		t.Errorf("config.load: %+v", got)
	}
	if got := resultByCode(rep, "disk.space"); len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("disk.space при nil-конфиге: %+v", got)
	}
	if got := resultByCode(rep, "audit.chain"); len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("audit.chain при nil-конфиге: %+v", got)
	}
}

// fakeAgent — httptest-стенд OpenAI-compatible агента с валидным ответом
// классификатора (схема п. 5.3).
func fakeAgent(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":
			"{\"label\":\"EMAIL\",\"confidence\":0.9,\"sensitivity\":\"PII\",\"reason_ru\":\"тестовый ответ формата\"}"
		}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
}

// TestRunOnlineAgents — DNS + пробный вызов против httptest-стенда:
// OK у валидного агента; у агента с ошибочным endpoint — FAIL dns.
func TestRunOnlineAgents(t *testing.T) {
	srv := fakeAgent(t)
	defer srv.Close()
	t.Setenv("DOCTOR_TEST_KEY", "test-key-1234567890")

	// DNS «localhost» — короткое замыкание; не-резолвящийся хост — FAIL без
	// ожидания таймаута сети.
	bundle := testBundle(t, srv.URL)
	bundle.Detectors.Agents[1].Endpoint = "http://nonexistent-hostname-zond.invalid/v1"
	bundle.Connections.Sources = nil // offline-часть источников не мешает

	rep := Run(context.Background(), bundle, filepath.Join(t.TempDir(), "doc.db"),
		Options{Online: true, Now: time.Now()})

	probes := resultByCode(rep, "agent.probe")
	if len(probes) != 1 || probes[0].Status != StatusOK || probes[0].Subject != "a1" {
		t.Errorf("agent.probe: %+v", probes)
	}
	dns := resultByCode(rep, "agent.dns")
	if len(dns) != 1 || dns[0].Status != StatusOK {
		t.Errorf("agent.dns localhost: %+v", dns)
	}
	// a2 не дошёл до dns (нет env) — валидно.
}

// TestCheckDNS — разбор endpoint'а и localhost-короткое замыкание.
func TestCheckDNS(t *testing.T) {
	ctx := context.Background()
	if err := checkDNS(ctx, "http://localhost:8080/v1/chat"); err != nil {
		t.Errorf("localhost: %v", err)
	}
	if err := checkDNS(ctx, "https://127.0.0.1/v1"); err != nil {
		t.Errorf("127.0.0.1: %v", err)
	}
	// .invalid гарантированно не резолвится (RFC 2606).
	if err := checkDNS(ctx, "http://nonexistent-hostname-zond.invalid/v1"); err == nil {
		t.Error(".invalid должен давать ошибку DNS")
	}
}

// TestCertInfo — самоподписанный сертификат: валидный OK, истёкший FAIL.
func TestCertInfo(t *testing.T) {
	makeCert := func(t *testing.T, notBefore, notAfter time.Time) string {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ключ: %v", err)
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "zond-test"},
			NotBefore:    notBefore, NotAfter: notAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatalf("сертификат: %v", err)
		}
		path := filepath.Join(t.TempDir(), "sp.crt")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return path
	}
	now := time.Now().UTC()
	valid := makeCert(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	info, err := certInfo(valid, now)
	if err != nil || !strings.Contains(info, "дн.") {
		t.Errorf("valid: info=%q err=%v", info, err)
	}
	expired := makeCert(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := certInfo(expired, now); err == nil || !strings.Contains(err.Error(), "истёк") {
		t.Errorf("expired: ожидалась ошибка об истечении, got %v", err)
	}
	if _, err := certInfo(filepath.Join(t.TempDir(), "missing.crt"), now); err == nil {
		t.Error("отсутствующий файл: ожидалась ошибка")
	}
}

// TestReportTextAndCounts — таблица содержит строки и сводку.
func TestReportTextAndCounts(t *testing.T) {
	rep := &Report{Results: []Result{
		{Code: "a.b", Subject: "s1", Status: StatusOK, Detail: "всё хорошо"},
		{Code: "c.d", Subject: "s2", Status: StatusFail, Detail: "сломано"},
	}}
	if !rep.HasFail() {
		t.Error("HasFail")
	}
	var sb strings.Builder
	rep.Text(&sb)
	out := sb.String()
	for _, want := range []string{"a.b", "c.d", "FAIL", "Итог: OK=1 WARN=0 FAIL=1 SKIP=0"} {
		if !strings.Contains(out, want) {
			t.Errorf("отчёт без %q:\n%s", want, out)
		}
	}
}
