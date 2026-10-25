package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

func TestDetectorsEditorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "detectors.yaml")
	if err := os.WriteFile(p, []byte(`# detectors — комментарий сохраняется
version: "1"

scan:
  profile: deep
  sample:
    mode: percent
    value: 5
    max_rows: 20000

ensemble:
  tau_accept: 0.8
  tau_review: 0.5
  weights:
    meta: 1.0
    rules: 1.5
    llm: 1.2

cluster:
  similarity: 0.8
  max_size: 100
`), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := OpenDetectorsEditor(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.View()
	if err != nil {
		t.Fatal(err)
	}
	if v.Profile != "deep" || v.TauAccept != 0.8 || v.WRules != 1.5 || v.MaxSize != 100 {
		t.Fatalf("view: %+v", v)
	}
	// правка + добавление proxy-секции
	v.TauReview = 0.4
	v.WLLM = 1.4
	v.MaxConcurrent = 4
	v.RateLimitRPS = 2.5
	v.CostScanLimitUSD = 7
	v.Offline = true
	if err := e.Apply(v); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	raw, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "комментарий сохраняется") {
		t.Fatalf("комментарий потерян:\n%s", s)
	}
	e2, err := OpenDetectorsEditor(p) // sanity: файл ещё старый, но парсится
	if err != nil {
		t.Fatalf("перечитывание файла: %v", err)
	}
	_ = e2
	var d Detectors
	dec := yaml.NewDecoder(strings.NewReader(s))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("итог не парсится: %v", err)
	}
	if d.Ensemble.TauReview != 0.4 || d.Ensemble.Weights["llm"] != 1.4 ||
		d.Proxy.MaxConcurrent != 4 || d.Proxy.RateLimitRPS != 2.5 ||
		d.Proxy.CostScanLimitUSD != 7 || !d.Proxy.Offline {
		t.Fatalf("значения не применились: %+v", d)
	}
	// отказ: tau_review >= tau_accept
	bad := v
	bad.TauReview = 0.9
	if err := e.Apply(bad); err == nil {
		t.Fatal("tau_review >= tau_accept: ожидалась ошибка валидации")
	}
	bad = v
	bad.Profile = "ultra"
	if err := e.Apply(bad); err == nil {
		t.Fatal("profile ultra: ожидалась ошибка")
	}
}
