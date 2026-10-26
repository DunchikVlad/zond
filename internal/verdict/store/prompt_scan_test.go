// Тесты S9-3: provenance пользовательского промпта в scans (миграция 0012,
// round-trip новых полей, честные DEFAULT'ы для старых записей).
package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// TestScanPromptFieldsRoundTrip — SaveScan/GetScan/ListScans/LastCheckpointScan
// сохраняют и возвращают prompt_base_version, prompt_hash, prompt_text, llm_enabled.
func TestScanPromptFieldsRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "prompt.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sc := &Scan{
		ID: "s1", SourceName: "ch", Profile: "deep", Status: "partial",
		StartedAt: time.Now().UTC(),
		// S9-3
		PromptBaseVersion: "2", PromptHash: "abc123", PromptText: "медицинская БД",
		LLMEnabled: true,
	}
	if err := st.SaveScan(t.Context(), sc); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetScan(t.Context(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if got.PromptBaseVersion != "2" || got.PromptHash != "abc123" ||
		got.PromptText != "медицинская БД" || !got.LLMEnabled {
		t.Fatalf("provenance промпта не round-trip: %+v", got)
	}

	list, _, err := st.ListScans(t.Context(), ScanFilter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("ListScans: %v, %+v", err, list)
	}
	if list[0].PromptHash != "abc123" || !list[0].LLMEnabled {
		t.Fatalf("ListScans теряет provenance: %+v", list[0])
	}
	last, err := st.LastCheckpointScan(t.Context(), "ch")
	if err != nil || last == nil {
		t.Fatalf("LastCheckpointScan: %v", err)
	}
	if last.PromptText != "медицинская БД" || !last.LLMEnabled {
		t.Fatalf("LastCheckpointScan теряет provenance: %+v", last)
	}

	// прогон со стандартным промптом — честные пустые значения
	if err := st.SaveScan(t.Context(), &Scan{
		ID: "s2", SourceName: "ch", Profile: "deep", Status: "done", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	plain, err := st.GetScan(t.Context(), "s2")
	if err != nil {
		t.Fatal(err)
	}
	if plain.PromptHash != "" || plain.PromptText != "" || plain.PromptBaseVersion != "" || plain.LLMEnabled {
		t.Fatalf("пустой provenance искажён: %+v", plain)
	}
}

// TestMigration0012ScanPrompt — upgrade с 0011: старые строки получают
// пустые provenance-поля (не угадываются); up/down/up восстанавливает схему.
func TestMigration0012ScanPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s93.db")
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
	if err := goose.DownTo(db, "migrations", 11); err != nil {
		db.Close()
		t.Fatal(err)
	}
	// «исторический» прогон до S9-3
	_, err = db.Exec(`INSERT INTO scans (id, source_name, profile, status, started_at, stats_json)
		VALUES ('legacy', 'ch', 'deep', 'partial', '2026-01-01T00:00:00Z', '{}')`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path) // upgrade на 0012
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := st.GetScan(t.Context(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.PromptBaseVersion != "" || legacy.PromptHash != "" ||
		legacy.PromptText != "" || legacy.LLMEnabled {
		t.Fatalf("legacy-строка угадана, а не сохранена: %+v", legacy)
	}
	// новый прогон на обновлённой схеме пишет provenance
	if err := st.SaveScan(t.Context(), &Scan{
		ID: "new", SourceName: "ch", Profile: "deep", Status: "running", StartedAt: time.Now().UTC(),
		PromptBaseVersion: "2", PromptHash: "h", PromptText: "текст", LLMEnabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// up/down/up
	db, err = openRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, "migrations", 11); err != nil {
		db.Close()
		t.Fatalf("down to 11: %v", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		db.Close()
		t.Fatalf("up: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	// после down/up колонки пересозданы с DEFAULT: строка читается, значения
	// provenance сброшены в пустые (DROP COLUMN необратимо теряет данные —
	// как и в тесте миграции 0011, здесь проверяется целостность схемы).
	got, err := st2.GetScan(t.Context(), "new")
	if err != nil || got.ID != "new" || got.PromptHash != "" || got.LLMEnabled {
		t.Fatalf("после up/down/up: %v, %+v", err, got)
	}
}
