// Тесты endpoint'ов описания БД (S9-4): POST /api/v1/scans/{id}/description-runs,
// GET /api/v1/scans/{id}/description-runs, GET /api/v1/description-runs/{id}.
package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// fakeDescriptionRunner — тестовый DescriptionRunner.
type fakeDescriptionRunner struct {
	runErr  error
	lastRun string // последний scan_id
	runs    int
}

func (f *fakeDescriptionRunner) Run(_ context.Context, scanID, _ string) (*store.DescriptionRun, error) {
	f.lastRun = scanID
	f.runs++
	if f.runErr != nil {
		return nil, f.runErr
	}
	return &store.DescriptionRun{
		ID: store.NewDescriptionRunID(), ScanID: scanID, Status: "done",
		PromptVersion: "1", AgentID: "agent1", Model: "gpt-4o",
		ResultJSON: `{"purpose_ru":"тестовое описание"}`,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func TestDescriptionStart(t *testing.T) {
	srv, st := newTestServer(t, WithDescriptionRunner(&fakeDescriptionRunner{}))
	mustScan(t, st, "sc1", "ch-test", "done")

	rec := do(t, srv, "POST", "/api/v1/scans/sc1/description-runs", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST description-runs: %d %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["status"] != "done" {
		t.Fatalf("status = %v, want done", m["status"])
	}
	if m["scan_id"] != "sc1" {
		t.Fatalf("scan_id = %v, want sc1", m["scan_id"])
	}
}

func TestDescriptionStartNotFound(t *testing.T) {
	srv, _ := newTestServer(t, WithDescriptionRunner(&fakeDescriptionRunner{}))
	rec := do(t, srv, "POST", "/api/v1/scans/nonexistent/description-runs", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST description-runs: %d, want 404", rec.Code)
	}
}

func TestDescriptionStartNotTerminal(t *testing.T) {
	srv, st := newTestServer(t, WithDescriptionRunner(&fakeDescriptionRunner{}))
	mustScan(t, st, "sc1", "ch-test", "running")

	rec := do(t, srv, "POST", "/api/v1/scans/sc1/description-runs", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST description-runs: %d %s, want 409", rec.Code, rec.Body.String())
	}
}

func TestDescriptionStartNoRunner(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "sc1", "ch-test", "done")

	rec := do(t, srv, "POST", "/api/v1/scans/sc1/description-runs", "")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("POST description-runs: %d, want 501", rec.Code)
	}
}

func TestDescriptionStartRunnerError(t *testing.T) {
	fr := &fakeDescriptionRunner{runErr: errors.New("LLM timeout")}
	srv, st := newTestServer(t, WithDescriptionRunner(fr))
	mustScan(t, st, "sc1", "ch-test", "done")

	rec := do(t, srv, "POST", "/api/v1/scans/sc1/description-runs", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST description-runs: %d %s, want 500", rec.Code, rec.Body.String())
	}
}

func TestDescriptionList(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "sc1", "ch-test", "done")

	// Создаём прогоны описания в store
	dr1 := &store.DescriptionRun{
		ID: store.NewDescriptionRunID(), ScanID: "sc1", Status: "done",
		PromptVersion: "1", CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveDescriptionRun(context.Background(), dr1); err != nil {
		t.Fatalf("SaveDescriptionRun: %v", err)
	}
	dr2 := &store.DescriptionRun{
		ID: store.NewDescriptionRunID(), ScanID: "sc1", Status: "failed",
		PromptVersion: "1", Error: "timeout", CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveDescriptionRun(context.Background(), dr2); err != nil {
		t.Fatalf("SaveDescriptionRun 2: %v", err)
	}

	rec := do(t, srv, "GET", "/api/v1/scans/sc1/description-runs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET description-runs: %d %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	items := m["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	if m["total"].(float64) != 2 {
		t.Fatalf("total = %v, want 2", m["total"])
	}
}

func TestDescriptionListNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/v1/scans/nonexistent/description-runs", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET description-runs: %d, want 404", rec.Code)
	}
}

func TestDescriptionGet(t *testing.T) {
	srv, st := newTestServer(t)
	mustScan(t, st, "sc1", "ch-test", "done")

	dr := &store.DescriptionRun{
		ID: store.NewDescriptionRunID(), ScanID: "sc1", Status: "done",
		PromptVersion: "1", ResultJSON: `{"purpose_ru":"тест"}`,
		CreatedAt: time.Now().UTC(),
	}
	if err := st.SaveDescriptionRun(context.Background(), dr); err != nil {
		t.Fatalf("SaveDescriptionRun: %v", err)
	}

	rec := do(t, srv, "GET", "/api/v1/description-runs/"+dr.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET description-run: %d %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["id"] != dr.ID {
		t.Fatalf("id = %v, want %s", m["id"], dr.ID)
	}
	if m["status"] != "done" {
		t.Fatalf("status = %v, want done", m["status"])
	}
}

func TestDescriptionGetNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/v1/description-runs/nonexistent", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET description-run: %d, want 404", rec.Code)
	}
}
