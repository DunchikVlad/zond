package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const editorFixture = `# connections.yaml — заголовочный комментарий сохраняется
version: "1"

sources:
  # тестовый контур
  - name: ch-test
    type: clickhouse
    dsn: "clickhouse://test:${CH_TEST_PASSWORD}@192.168.31.119:9000/default"
    schedule: "0 2 * * *" # ежедночно
    scan_window: "02:00-06:00"
  - name: mongo-test
    type: mongodb
    uri: "mongodb://test:${MONGO_TEST_PASSWORD}@192.168.31.119:27017/testdb"

sso:
  enabled: false
`

func openEditor(t *testing.T, content string) *SourceEditor {
	t.Helper()
	p := filepath.Join(t.TempDir(), "connections.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := OpenSourceEditor(p)
	if err != nil {
		t.Fatalf("OpenSourceEditor: %v", err)
	}
	return e
}

func TestSourceEditorListPreservesRaw(t *testing.T) {
	e := openEditor(t, editorFixture)
	srcs, err := e.Sources()
	if err != nil {
		t.Fatalf("Sources: %v", err)
	}
	if len(srcs) != 2 {
		t.Fatalf("источников: %d", len(srcs))
	}
	if srcs[0].DSN != "clickhouse://test:${CH_TEST_PASSWORD}@192.168.31.119:9000/default" {
		t.Fatalf("dsn без интерполяции: %q", srcs[0].DSN)
	}
	if srcs[0].Schedule != "0 2 * * *" || srcs[0].ScanWindow != "02:00-06:00" {
		t.Fatalf("schedule/window: %+v", srcs[0])
	}
}

func TestSourceEditorUpsertNewAndUpdate(t *testing.T) {
	e := openEditor(t, editorFixture)
	add := SourceEntry{Name: "ch-stand-2", Type: "clickhouse",
		DSN: "clickhouse://test:${CH2_PW}@192.168.31.120:9000/default", Schedule: "*/15 * * * *"}
	if err := e.Upsert(add); err != nil {
		t.Fatalf("Upsert add: %v", err)
	}
	upd := SourceEntry{Name: "ch-test", Type: "clickhouse",
		DSN:      "clickhouse://test:${CH_TEST_PASSWORD}@192.168.31.119:9000/default",
		Schedule: "0 3 * * *", ScanWindow: "03:00-05:00"}
	if err := e.Upsert(upd); err != nil {
		t.Fatalf("Upsert update: %v", err)
	}
	srcs, err := e.Sources()
	if err != nil || len(srcs) != 3 {
		t.Fatalf("после upsert: %v %d", err, len(srcs))
	}
	if srcs[0].Schedule != "0 3 * * *" || srcs[0].ScanWindow != "03:00-05:00" {
		t.Fatalf("update не применился: %+v", srcs[0])
	}
	raw, err := e.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	s := string(raw)
	// секционные комментарии и ${ENV} сохранены (inline-комментарий
	// редактируемой строки не переживает замену значения — ожидаемо).
	if !strings.Contains(s, "заголовочный комментарий сохраняется") || !strings.Contains(s, "тестовый контур") {
		t.Fatalf("комментарии потеряны:\n%s", s)
	}
	if !strings.Contains(s, "${CH_TEST_PASSWORD}") || !strings.Contains(s, "${CH2_PW}") {
		t.Fatalf("${ENV} потеряны:\n%s", s)
	}
	if err := e.ValidateAll(); err != nil {
		t.Fatalf("ValidateAll: %v", err)
	}
}

func TestSourceEditorDelete(t *testing.T) {
	e := openEditor(t, editorFixture)
	if err := e.Delete("mongo-test"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := e.Delete("ghost"); err == nil {
		t.Fatal("удаление несуществующего: ожидалась ошибка")
	}
	srcs, _ := e.Sources()
	if len(srcs) != 1 || srcs[0].Name != "ch-test" {
		t.Fatalf("после delete: %+v", srcs)
	}
}

func TestSourceEntryValidate(t *testing.T) {
	bad := []SourceEntry{
		{Name: "has space", Type: "clickhouse", DSN: "clickhouse://u:${PW}@h/db"},
		{Name: "s", Type: "oracle", DSN: "x"},
		{Name: "s", Type: "clickhouse"},                                    // без dsn
		{Name: "s", Type: "clickhouse", DSN: "clickhouse://u:secret@h/db"}, // пароль открытым текстом
		{Name: "s", Type: "mongodb", URI: "mongodb://u:secret@h/db"},       // то же для mongo
		{Name: "s", Type: "clickhouse", DSN: "clickhouse://u:${PW}@h/db", Schedule: "не cron"},
		{Name: "s", Type: "clickhouse", DSN: "clickhouse://u:${PW}@h/db", ScanWindow: "25:00-26:00"},
		{Name: "s", Type: "clickhouse", DSN: "clickhouse://u:${PW}@h/db", ScanWindow: "03:00-03:00"},
	}
	for _, se := range bad {
		if err := se.Validate(); err == nil {
			t.Errorf("Validate(%+v): ожидалась ошибка", se)
		}
	}
	good := SourceEntry{Name: "s-1_ok", Type: "mongodb", URI: "mongodb://u:${MONGO_PW}@h:27017/db",
		Schedule: "0 2 * * *", ScanWindow: "22:00-02:00"}
	if err := good.Validate(); err != nil {
		t.Errorf("Validate(good): %v", err)
	}
}
