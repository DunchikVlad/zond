package store

import (
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigrationPreservesLegacyScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := openRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, "migrations", 9); err != nil {
		db.Close()
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO scans
		(id, source_name, profile, status, started_at, stats_json)
		VALUES ('legacy', 'ch', 'deep', 'partial', '2026-01-01T00:00:00Z', '{}')`)
	if err == nil {
		_, err = db.Exec(`INSERT INTO scan_tables (scan_id, table_name, status)
			VALUES ('legacy', 'users', 'done')`)
	}
	if err == nil {
		_, err = db.Exec(`INSERT INTO verdicts
			(id, scan_id, table_name, path, native_type, label, sensitivity, confidence,
			 evidence_layer, review_status, created_at)
			VALUES ('legacy-verdict', 'legacy', 'users', 'email', 'String', 'EMAIL', 'PII',
			 0.9, 'ensemble', 'auto_accepted', '2026-01-01T00:00:00Z')`)
	}
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sc, err := st.GetScan(t.Context(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if sc.TableIdentityVersion != 1 || sc.ConfigFingerprint != "" || sc.BinaryVersion != "" {
		t.Fatalf("legacy provenance искажён: %+v", sc)
	}
	done, err := st.DoneTables(t.Context(), "legacy")
	if err != nil || !done["users"] {
		t.Fatalf("legacy checkpoint: %v, err=%v", done, err)
	}
	vs, err := st.ListVerdicts(t.Context(), "legacy")
	if err != nil || len(vs) != 1 || vs[0].ID != "legacy-verdict" || vs[0].Table != "users" {
		t.Fatalf("legacy verdict изменён: %+v, err=%v", vs, err)
	}
}
