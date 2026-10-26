package api

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/DunchikVlad/zond/internal/scanengine"
)

func TestScanResume(t *testing.T) {
	runner := &fakeRunner{started: map[string]string{}}
	srv, _ := newTestServer(t, WithRunner(runner))
	rec := do(t, srv, "POST", "/api/v1/scans/old/resume", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("resume: %d: %s", rec.Code, rec.Body.String())
	}
	m := decode(t, rec)
	if m["scan_id"] != "resumed-old" || m["resume_from"] != "old" || len(runner.resumed) != 1 {
		t.Fatalf("ответ resume: %v, calls=%v", m, runner.resumed)
	}

	runner.resumeErr = sql.ErrNoRows
	if rec := do(t, srv, "POST", "/api/v1/scans/missing/resume", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing: %d", rec.Code)
	}
	runner.resumeErr = &ScanConflictError{Reason: "done"}
	if rec := do(t, srv, "POST", "/api/v1/scans/done/resume", ""); rec.Code != http.StatusConflict {
		t.Fatalf("done: %d", rec.Code)
	}
	runner.resumeErr = &scanengine.ResumeCompatibilityError{Mismatches: []scanengine.ResumeMismatch{
		{Field: "taxonomy_version", Stored: "1", Current: "2"},
		{Field: "binary_version", Stored: "old", Current: "new"},
	}}
	rec = do(t, srv, "POST", "/api/v1/scans/old/resume", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("incompatible: %d: %s", rec.Code, rec.Body.String())
	}
	errObj := decode(t, rec)["error"].(map[string]any)
	if errObj["code"] != CodeResumeIncompatible {
		t.Fatalf("код: %v", errObj)
	}
	details := errObj["details"].(map[string]any)
	if len(details["mismatches"].([]any)) != 2 {
		t.Fatalf("не все различия: %v", details)
	}
}

func TestScanResumeWithoutRunner(t *testing.T) {
	srv, _ := newTestServer(t)
	if rec := do(t, srv, "POST", "/api/v1/scans/old/resume", ""); rec.Code != http.StatusNotImplemented {
		t.Fatalf("без runner: %d", rec.Code)
	}
}
