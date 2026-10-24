package audit

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// sinkTestDB — in-memory SQLite с миграциями store (audit_log +
// audit_sink_state, 0009). Пакет audit не тянет store (граница слоёв),
// поэтому тест поднимает схему сам: embed-миграции store недоступны —
// создаём минимальный контур (триггеры audit_log опускаем, нас интересует
// механика sink, а не защита журнала — она покрыта store-тестами).
func sinkTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	ddl := []string{
		`CREATE TABLE audit_log (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL, actor TEXT NOT NULL, category TEXT NOT NULL,
			action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
			details_json TEXT NOT NULL DEFAULT '{}',
			prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)`,
		`CREATE TABLE audit_sink_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_seq INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			updated_at TEXT)`,
		`INSERT INTO audit_sink_state (id) VALUES (1)`,
	}
	for _, q := range ddl {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("схема: %v", err)
		}
	}
	return db
}

// sinkAppend — запись события через AppendTx (как store.AppendAudit).
func sinkAppend(t *testing.T, db *sql.DB, actions ...string) {
	t.Helper()
	events := make([]Event, 0, len(actions))
	for _, a := range actions {
		events = append(events, Event{
			Actor: "cli", Category: CatScan, Action: a, Target: "scan:s1",
			TS: time.Now().UTC(),
		})
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	if err := AppendTx(context.Background(), tx, events); err != nil {
		t.Fatalf("AppendTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// memSink — in-memory «SIEM»: принимает записи через подменённый dial.
// Запись одного события синхронна: reader сигналит о получении payload
// до ответа dial — после Pump записи гарантированно учтены (без гонок
// горутин на net.Pipe).
type memSink struct {
	mu    sync.Mutex
	got   []string
	fail  int         // первые N доставок падают (недоступность sink)
	readC chan string // reader отдаёт принятое сюда до конца dial
}

func (m *memSink) dial(network, address string) (net.Conn, error) {
	m.mu.Lock()
	if m.fail > 0 {
		m.fail--
		m.mu.Unlock()
		return nil, errors.New("sink недоступен (тест)")
	}
	if m.readC == nil {
		m.readC = make(chan string, SinkBatch+1)
	}
	m.mu.Unlock()
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 64*1024)
		n, err := c2.Read(buf) // одна запись = одно событие (deliverTCP)
		if n > 0 {
			m.mu.Lock()
			m.got = append(m.got, string(buf[:n]))
			m.mu.Unlock()
			m.readC <- string(buf[:n]) // сигнал: запись принята до возврата dial
		}
		if err != nil {
			return
		}
		// дочитываем до закрытия (клиент закроет после записи)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()
	return syncConn{Conn: c1, readC: m.readC}, nil
}

// syncConn оборачивает конец пайпа: Close дожидается приёма записи
// reader'ом (детерминированный assert после Pump).
type syncConn struct {
	net.Conn
	readC chan string
}

func (c syncConn) Close() error {
	err := c.Conn.Close()
	<-c.readC // reader подтвердил запись до возврата из deliver
	return err
}

func (m *memSink) lines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]string{}, m.got...)
	return out
}

func newTestSink(db *sql.DB, ms *memSink, kind SinkKind) *Sink {
	s := NewSink(db, SinkConfig{Kind: kind, Address: "mem:0"}, nil)
	s.dial = ms.dial
	return s
}

// TestSinkDeliversInOrder — воркер доставляет события в порядке цепочки и
// двигает закладку: повторный Pump не дублирует (п. 14.2).
func TestSinkDeliversInOrder(t *testing.T) {
	db := sinkTestDB(t)
	sinkAppend(t, db, "scan_start", "scan_finish")

	ms := &memSink{}
	s := newTestSink(db, ms, SinkJSONTCP)
	n, err := s.Pump(context.Background())
	if err != nil {
		t.Fatalf("Pump: %v", err)
	}
	if n != 2 {
		t.Fatalf("доставлено %d, ожидалось 2", n)
	}
	last, err := SinkLastSeq(context.Background(), db)
	if err != nil {
		t.Fatalf("SinkLastSeq: %v", err)
	}
	if last != 2 {
		t.Fatalf("закладка %d, ожидалась 2", last)
	}
	// Порядок и формат: две NDJSON-строки (canonical с "\n"), seq по возрастанию.
	got := strings.Join(ms.lines(), "")
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("строк на проводе: %d, ожидалось 2", len(lines))
	}
	if !strings.Contains(lines[0], `"seq":1`) || !strings.Contains(lines[1], `"seq":2`) {
		t.Fatalf("порядок/seq на проводе: %q", lines)
	}
	// Повторный Pump — пусто (закладка за хвостом), дублей нет.
	n, err = s.Pump(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("повторный Pump: n=%d err=%v, ожидалось 0/nil", n, err)
	}
	if got := len(strings.Split(strings.TrimRight(strings.Join(ms.lines(), ""), "\n"), "\n")); got != 2 {
		t.Fatalf("дубли на проводе: строк %d, ожидалось 2", got)
	}
}

// TestSinkRetryAfterFailure — недоступный sink: закладка не двигается,
// события не теряются; после восстановления доставка догоняет (п. 14.2
// «локальная очередь с повторной отправкой»).
func TestSinkRetryAfterFailure(t *testing.T) {
	db := sinkTestDB(t)
	sinkAppend(t, db, "scan_start")

	ms := &memSink{fail: 2} // две попытки падают
	s := newTestSink(db, ms, SinkJSONTCP)
	for i := 0; i < 2; i++ {
		if _, err := s.Pump(context.Background()); err != nil {
			t.Fatalf("Pump (fail %d): %v", i, err)
		}
		last, _ := SinkLastSeq(context.Background(), db)
		if last != 0 {
			t.Fatalf("закладка сдвинулась при недоступном sink: %d", last)
		}
		var lastErr string
		if err := db.QueryRow(`SELECT last_error FROM audit_sink_state WHERE id = 1`).Scan(&lastErr); err != nil {
			t.Fatalf("last_error: %v", err)
		}
		if lastErr == "" {
			t.Fatal("last_error не зафиксирован при неудаче")
		}
	}
	// Восстановление: доставка и продвижение закладки.
	n, err := s.Pump(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("Pump после восстановления: n=%d err=%v", n, err)
	}
	last, _ := SinkLastSeq(context.Background(), db)
	if last != 1 {
		t.Fatalf("закладка %d, ожидалась 1", last)
	}
	// last_error сброшен после успеха.
	var lastErr string
	_ = db.QueryRow(`SELECT last_error FROM audit_sink_state WHERE id = 1`).Scan(&lastErr)
	if lastErr != "" {
		t.Fatalf("last_error не сброшен: %q", lastErr)
	}
}

// TestSinkNoEventLostOnAppendDuringDelivery — событие, записанное между
// циклами, доставляется следующим Pump (потеря недопустима, п. 14.2).
func TestSinkNoEventLostOnAppendDuringDelivery(t *testing.T) {
	db := sinkTestDB(t)
	sinkAppend(t, db, "scan_start")
	ms := &memSink{}
	s := newTestSink(db, ms, SinkJSONTCP)
	if n, _ := s.Pump(context.Background()); n != 1 {
		t.Fatalf("Pump 1: n=%d", n)
	}
	sinkAppend(t, db, "scan_finish") // записано после первого цикла
	n, _ := s.Pump(context.Background())
	if n != 1 {
		t.Fatalf("Pump 2: n=%d, ожидалось 1 (догон)", n)
	}
	last, _ := SinkLastSeq(context.Background(), db)
	if last != 2 {
		t.Fatalf("закладка %d, ожидалась 2", last)
	}
}

// TestSinkSyslogCEF — syslog-вид: полезная нагрузка — CEF-строка с
// канонической записью в msg (п. 14.2, syslog/CEF).
func TestSinkSyslogCEF(t *testing.T) {
	db := sinkTestDB(t)
	sinkAppend(t, db, "scan_start")
	ms := &memSink{}
	s := NewSink(db, SinkConfig{Kind: SinkSyslog, Address: "mem:0", Proto: "udp"}, nil)
	s.dial = ms.dial
	if _, err := s.Pump(context.Background()); err != nil {
		t.Fatalf("Pump: %v", err)
	}
	got := strings.Join(ms.lines(), "")
	if !strings.HasPrefix(got, "CEF:0|DunchikVlad|zond|1|1|audit|") {
		t.Fatalf("не CEF-фрейминг: %q", got)
	}
	if !strings.Contains(got, "msg={") || !strings.Contains(got, `"seq":1`) {
		t.Fatalf("msg без канонической записи: %q", got)
	}
}

// TestSinkPending — агрегат backlog для doctor (п. 17): недоставленный
// хвост журнала за закладкой.
func TestSinkPending(t *testing.T) {
	db := sinkTestDB(t)
	sinkAppend(t, db, "a", "b", "c")
	n, err := SinkPending(context.Background(), db)
	if err != nil || n != 3 {
		t.Fatalf("pending: n=%d err=%v, ожидалось 3/nil", n, err)
	}
	ms := &memSink{}
	s := newTestSink(db, ms, SinkJSONTCP)
	if _, err := s.Pump(context.Background()); err != nil {
		t.Fatalf("Pump: %v", err)
	}
	n, _ = SinkPending(context.Background(), db)
	if n != 0 {
		t.Fatalf("pending после доставки: %d", n)
	}
}

// TestSinkNilSafe — нулевой приёмник = sink выключен (опция п. 14.2).
func TestSinkNilSafe(t *testing.T) {
	var s *Sink
	if s.Enabled() {
		t.Fatal("nil sink не должен быть Enabled")
	}
	n, err := s.Pump(context.Background())
	if n != 0 || err != nil {
		t.Fatalf("nil Pump: n=%d err=%v", n, err)
	}
	if NewSink(nil, SinkConfig{Kind: SinkJSONTCP}, nil) != nil {
		t.Fatal("nil db должен давать nil sink")
	}
	if NewSink(sinkTestDB(t), SinkConfig{}, nil) != nil {
		t.Fatal("пустой конфиг должен давать nil sink")
	}
}
