package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

const sourceS91Fixture = `version: '1'
sources:
  - name: existing
    type: clickhouse
    dsn: '${DSN}'
`

func newSourceS91Server(t *testing.T, opts ...Option) (*Server, string, *store.Store) {
	t.Helper()
	st := fixtureStore(t)
	path := filepath.Join(t.TempDir(), "connections.yaml")
	if err := os.WriteFile(path, []byte(sourceS91Fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	opts = append([]Option{WithConnsPath(path)}, opts...)
	srv, err := New(st, nil, nil, false, &fakeRunner{}, testBundle(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return srv, path, st
}

func postSourceS91(t *testing.T, srv *Server, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set(csrfField, testCSRFToken)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCSRF(req)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func sourceFormS91(name string) url.Values {
	return url.Values{"name": {name}, "type": {"clickhouse"}, "dsn": {"${DSN}"}}
}

func TestSourcePingEscapesHTML(t *testing.T) {
	srv, _, _ := newSourceS91Server(t)
	form := sourceFormS91(`<img src=x onerror=alert(1)>`)
	form["dsn"][0] = "not-a-url"
	rec := postSourceS91(t, srv, "/sources/test", form)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "<img") || !strings.Contains(rec.Body.String(), "&lt;img") {
		t.Fatalf("HTMX XSS: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSourceApplyFailureRollsBack(t *testing.T) {
	srv, path, _ := newSourceS91Server(t, WithApplyConns(func(config.SourceEntry) (*config.Connections, error) {
		return nil, fmt.Errorf("apply failed")
	}))
	before, _ := os.ReadFile(path)
	rec := postSourceS91(t, srv, "/sources/save", sourceFormS91("new-source"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("файл не откачен:\n%s", after)
	}
}

func TestSourceDeleteApplyFailureRollsBack(t *testing.T) {
	srv, path, _ := newSourceS91Server(t, WithApplyConns(func(config.SourceEntry) (*config.Connections, error) {
		return nil, fmt.Errorf("apply failed")
	}))
	before, _ := os.ReadFile(path)
	rec := postSourceS91(t, srv, "/sources/existing/delete", url.Values{})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("удаление не откачено:\n%s", after)
	}
}

func TestSourceAuditFailureRollsBackAndReapplies(t *testing.T) {
	calls := 0
	srv, path, st := newSourceS91Server(t, WithApplyConns(func(config.SourceEntry) (*config.Connections, error) {
		calls++
		return &config.Connections{}, nil
	}))
	before, _ := os.ReadFile(path)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	rec := postSourceS91(t, srv, "/sources/save", sourceFormS91("new-source"))
	if rec.Code != http.StatusInternalServerError || calls != 2 {
		t.Fatalf("audit failure: status=%d apply calls=%d", rec.Code, calls)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatalf("файл не откачен после аудита:\n%s", after)
	}
}

func TestSourceConcurrentSavesDoNotLoseUpdates(t *testing.T) {
	srv, path, _ := newSourceS91Server(t, WithApplyConns(func(config.SourceEntry) (*config.Connections, error) {
		return &config.Connections{}, nil
	}))
	const n = 8
	var wg sync.WaitGroup
	statuses := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := postSourceS91(t, srv, "/sources/save", sourceFormS91(fmt.Sprintf("source-%d", i)))
			statuses <- rec.Code
		}(i)
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusSeeOther {
			t.Fatalf("concurrent save: %d", status)
		}
	}
	e, err := config.OpenSourceEditor(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := e.Sources()
	if err != nil || len(entries) != n+1 {
		t.Fatalf("потеряны параллельные правки: %d, err=%v", len(entries), err)
	}
	tmp, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".connections.yaml-*.tmp"))
	if err != nil || len(tmp) != 0 {
		t.Fatalf("остались временные файлы: %v, err=%v", tmp, err)
	}
}

func TestSourceLimitsAndStrictFormInts(t *testing.T) {
	srv, path, _ := newSourceS91Server(t)
	form := sourceFormS91("limited")
	form.Set("max_concurrent_scans", "2")
	form.Set("max_concurrent_tables", "3")
	form.Set("query_timeout_s", "45")
	if rec := postSourceS91(t, srv, "/sources/save", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("save limits: %d %s", rec.Code, rec.Body.String())
	}
	e, _ := config.OpenSourceEditor(path)
	entries, _ := e.Sources()
	got := entries[len(entries)-1]
	if got.MaxConcurrentScans != 2 || got.MaxConcurrentTables != 3 || got.QueryTimeoutS != 45 {
		t.Fatalf("limits: %+v", got)
	}
	bad := sourceFormS91("bad-int")
	bad.Set("query_timeout_s", "abc")
	before, _ := os.ReadFile(path)
	if rec := postSourceS91(t, srv, "/sources/save", bad); rec.Code != http.StatusSeeOther {
		t.Fatalf("bad int redirect: %d", rec.Code)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("невалидное число изменило файл")
	}
}
