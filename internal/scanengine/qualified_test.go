package scanengine

import (
	"context"
	"iter"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

type qualifiedConnector struct {
	calls map[string]int
}

func (c *qualifiedConnector) Ping(context.Context) error { return nil }
func (c *qualifiedConnector) Close() error               { return nil }
func (c *qualifiedConnector) ListTables(context.Context) ([]connector.TableRef, error) {
	return []connector.TableRef{{Schema: "sales", Name: "users"}, {Schema: "archive", Name: "users"}}, nil
}
func (c *qualifiedConnector) GetSchema(_ context.Context, t connector.TableRef) ([]connector.Column, error) {
	c.calls[t.QualifiedName()]++
	return []connector.Column{{Name: "email", NativeType: "String"}}, nil
}
func (c *qualifiedConnector) CountRows(context.Context, connector.TableRef) (int64, error) {
	return 1, nil
}
func (c *qualifiedConnector) Sample(_ context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	value := "sales@example.com"
	if spec.Table.Schema == "archive" {
		value = "archive@example.com"
	}
	return func(yield func(connector.Row, error) bool) {
		yield(connector.Row{"email": value}, nil)
	}, nil
}

func TestQualifiedTableIdentityAndResume(t *testing.T) {
	eng, st := testEngine(t)
	conn := &qualifiedConnector{calls: map[string]int{}}
	rep, err := eng.Scan(context.Background(), conn, "fake", "deep")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := st.ListVerdicts(context.Background(), rep.ScanID)
	if err != nil || len(vs) != 2 {
		t.Fatalf("вердикты: %+v, err=%v", vs, err)
	}
	if vs[0].ID == vs[1].ID || vs[0].Table == vs[1].Table {
		t.Fatalf("qualified identity потеряна: %+v", vs)
	}
	tables, err := st.ScanTables(context.Background(), rep.ScanID)
	if err != nil || len(tables) != 2 {
		t.Fatalf("чекпоинты: %+v, err=%v", tables, err)
	}

	prev := &store.Scan{
		ID: "resume-qualified", SourceName: "fake", Profile: "deep", Status: "partial",
		StartedAt: time.Now().UTC(), TableIdentityVersion: store.TableIdentityQualified,
		ConfigFingerprint: eng.cfg.ConfigFingerprint, TaxonomyVersion: eng.cfg.TaxonomyVersion,
		DetectorsVersion: eng.cfg.DetectorsVersion, BinaryVersion: eng.cfg.BinaryVersion,
	}
	if err := st.SaveScan(context.Background(), prev); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTable(context.Background(), prev.ID, "sales.users", 1, "done", "", ""); err != nil {
		t.Fatal(err)
	}
	resumeConn := &qualifiedConnector{calls: map[string]int{}}
	eng.cfg.ResumeFrom = prev.ID
	resumed, err := eng.Scan(context.Background(), resumeConn, "fake", "deep")
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Skipped != 1 || resumeConn.calls["sales.users"] != 0 || resumeConn.calls["archive.users"] != 1 {
		t.Fatalf("resume по qualified name: rep=%+v calls=%v", resumed, resumeConn.calls)
	}
}
