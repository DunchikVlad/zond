package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- ParseWindow (п. 13.2, scan_window) ---

func TestParseWindowValid(t *testing.T) {
	cases := []struct {
		in         string
		start, end int // минуты от полуночи
	}{
		{"02:00-06:00", 120, 360},
		{"00:00-23:59", 0, 1439},
		{"22:00-02:00", 1320, 120}, // через полночь
	}
	for _, c := range cases {
		w, err := ParseWindow(c.in)
		if err != nil {
			t.Fatalf("ParseWindow(%q): %v", c.in, err)
		}
		if w.startMin != c.start || w.endMin != c.end {
			t.Errorf("ParseWindow(%q) = %d-%d, ожидалось %d-%d", c.in, w.startMin, w.endMin, c.start, c.end)
		}
	}
}

func TestParseWindowRejected(t *testing.T) {
	for _, in := range []string{
		"",              // пусто
		"02:00",         // нет дефиса
		"02:00-",        // нет конца
		"-06:00",        // нет начала
		"2:00-06:00",    // нестрогий час (без ведущего нуля)
		"02:00-6:00",    // нестрогий час конца
		"02:00-06:00 ",  // хвостовой пробел
		" 02:00-06:00",  // ведущий пробел
		"24:00-06:00",   // час вне диапазона
		"02:60-06:00",   // минуты вне диапазона
		"02:00-02:00",   // start == end — двусмысленно (0ч или 24ч)
		"02:00-06:00-в", // лишний сегмент
		"ab:cd-ef:gh",   // не числа
	} {
		if _, err := ParseWindow(in); err == nil {
			t.Errorf("ParseWindow(%q) должен отклоняться", in)
		}
	}
}

// --- Window.Contains ---

func at(hour, min int) time.Time {
	return time.Date(2026, 10, 24, hour, min, 0, 0, time.Local)
}

func TestWindowContains(t *testing.T) {
	w, err := ParseWindow("02:00-06:00")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		now  time.Time
		want bool
	}{
		{at(1, 59), false}, // до окна
		{at(2, 0), true},   // начало включительно
		{at(4, 30), true},  // внутри
		{at(5, 59), true},  // последняя минута
		{at(6, 0), false},  // конец исключителен
		{at(23, 0), false}, // после окна
	}
	for _, c := range cases {
		if got := w.Contains(c.now); got != c.want {
			t.Errorf("Contains(%02d:%02d) = %v, ожидалось %v", c.now.Hour(), c.now.Minute(), got, c.want)
		}
	}
}

func TestWindowContainsMidnightCrossing(t *testing.T) {
	w, err := ParseWindow("22:00-02:00")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		now  time.Time
		want bool
	}{
		{at(21, 59), false},
		{at(22, 0), true},
		{at(23, 59), true},
		{at(0, 0), true}, // полночь внутри окна через сутки
		{at(1, 59), true},
		{at(2, 0), false}, // конец исключителен
		{at(12, 0), false},
	}
	for _, c := range cases {
		if got := w.Contains(c.now); got != c.want {
			t.Errorf("midnight Contains(%02d:%02d) = %v, ожидалось %v", c.now.Hour(), c.now.Minute(), got, c.want)
		}
	}
}

// --- Window.NextStart ---

func TestWindowNextStart(t *testing.T) {
	w, err := ParseWindow("02:00-06:00")
	if err != nil {
		t.Fatal(err)
	}
	// Внутри окна → тот же момент.
	if got := w.NextStart(at(3, 15)); !got.Equal(at(3, 15)) {
		t.Errorf("NextStart внутри окна = %v, ожидался тот же момент", got)
	}
	// До окна → сегодня 02:00.
	if got := w.NextStart(at(1, 0)); !got.Equal(at(2, 0)) {
		t.Errorf("NextStart до окна = %v, ожидалось сегодня 02:00", got)
	}
	// После окна → завтра 02:00.
	want := time.Date(2026, 10, 25, 2, 0, 0, 0, time.Local)
	if got := w.NextStart(at(7, 0)); !got.Equal(want) {
		t.Errorf("NextStart после окна = %v, ожидалось %v", got, want)
	}
}

func TestWindowNextStartMidnightCrossing(t *testing.T) {
	w, err := ParseWindow("22:00-02:00")
	if err != nil {
		t.Fatal(err)
	}
	// 03:00 вне окна → сегодня 22:00.
	if got := w.NextStart(at(3, 0)); !got.Equal(at(22, 0)) {
		t.Errorf("NextStart(03:00) = %v, ожидалось 22:00 того же дня", got)
	}
	// 23:00 внутри окна → now.
	if got := w.NextStart(at(23, 0)); !got.Equal(at(23, 0)) {
		t.Errorf("NextStart(23:00) = %v, ожидался тот же момент", got)
	}
	// 21:00 вне → сегодня 22:00.
	if got := w.NextStart(at(21, 0)); !got.Equal(at(22, 0)) {
		t.Errorf("NextStart(21:00) = %v, ожидалось 22:00", got)
	}
}

// --- Валидация connections.yaml (S8-2 поля источника, п. 13.2) ---

func TestConnectionsScanWindowValidation(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - name: ch-ok
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
    scan_window: "02:00-06:00"
  - name: ch-bad
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
    scan_window: "2:00-06:00"
`)
	_, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
	if err == nil || !strings.Contains(err.Error(), "scan_window") {
		t.Fatalf("битый scan_window должен отклоняться при загрузке: %v", err)
	}
}

func TestConnectionsNegativeLimitsRejected(t *testing.T) {
	setValidEnv(t)
	for _, field := range []string{"max_concurrent_scans", "max_concurrent_tables", "query_timeout_s"} {
		dir := validDir(t)
		writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - name: ch
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
    `+field+`: -1
`)
		_, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("%s: -1 должен отклоняться: %v", field, err)
		}
	}
}

func TestSourceLimitDefaults(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - name: ch
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
  - name: ch-custom
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
    max_concurrent_scans: 3
    max_concurrent_tables: 5
    query_timeout_s: 60
`)
	c, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
	if err != nil {
		t.Fatalf("LoadConnections: %v", err)
	}
	plain, custom := c.Sources[0], c.Sources[1]
	// Дефолты спецификации (п. 13.2): 0/опущено → 1/2/300с.
	if plain.ScansLimit() != 1 || plain.TablesLimit() != 2 || plain.QueryTimeout() != 300*time.Second {
		t.Errorf("дефолты: scans=%d tables=%d timeout=%v, ожидалось 1/2/300s",
			plain.ScansLimit(), plain.TablesLimit(), plain.QueryTimeout())
	}
	if custom.ScansLimit() != 3 || custom.TablesLimit() != 5 || custom.QueryTimeout() != time.Minute {
		t.Errorf("явные лимиты не применены: scans=%d tables=%d timeout=%v",
			custom.ScansLimit(), custom.TablesLimit(), custom.QueryTimeout())
	}
	if plain.ScanWindow != "" {
		t.Errorf("scan_window без поля должен быть пустым, %q", plain.ScanWindow)
	}
}

// --- audit.sink (S8-3, п. 14.2) ---

func TestConnectionsAuditSinkValidation(t *testing.T) {
	setValidEnv(t)
	cases := []struct {
		name    string
		sink    string
		wantErr string // пусто — валидно
	}{
		{"без блока", "", ""},
		{"json-tcp", `sink: {kind: json-tcp, address: "siem:5140"}`, ""},
		{"syslog udp default", `sink: {kind: syslog, address: "siem:514"}`, ""},
		{"syslog tcp", `sink: {kind: syslog, address: "siem:514", proto: tcp}`, ""},
		{"kind без address", `sink: {kind: json-tcp}`, "audit.sink"},
		{"address без kind", `sink: {address: "siem:5140"}`, "audit.sink"},
		{"неизвестный kind", `sink: {kind: kafka, address: "siem:5140"}`, "json-tcp|syslog"},
		{"proto не udp/tcp", `sink: {kind: syslog, address: "siem:514", proto: sctp}`, "udp|tcp"},
		{"proto при json-tcp", `sink: {kind: json-tcp, address: "siem:5140", proto: udp}`, "proto"},
		{"address не host:port", `sink: {kind: json-tcp, address: "siem"}`, "host:port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := validDir(t)
			yaml := `version: "1"
sources: []
`
			if c.sink != "" {
				yaml += "audit:\n  " + c.sink + "\n"
			}
			writeFile(t, dir, "connections.yaml", yaml)
			_, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("валидный sink отклонён: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("ожидалась ошибка %q: %v", c.wantErr, err)
			}
		})
	}
}
