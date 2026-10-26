package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

func TestScanResumeUI(t *testing.T) {
	st := fixtureStore(t)
	runner := &fakeRunner{}
	ts, _ := newTestServer(t, st, nil, false, runner)
	if err := st.SaveScan(t.Context(), &store.Scan{
		ID: "partial-1", SourceName: "ch-test", Profile: "deep", Status: "partial", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, ts.Client(), ts.URL+"/scans")
	if !strings.Contains(body, `action="/scans/partial-1/resume"`) {
		t.Fatalf("кнопка resume отсутствует: %s", body)
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/scans/partial-1/resume", nil)
	addCSRF(req)
	client := *ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/scans/scan-resumed" || runner.resumed != "partial-1" {
		t.Fatalf("resume: status=%d location=%q resumed=%q", resp.StatusCode, resp.Header.Get("Location"), runner.resumed)
	}
}
