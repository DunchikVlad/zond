// Тест мягкой остановки прогона (инкремент 5б, blueprint п. 11.2 stop):
// отмена ctx между таблицами → статус interrupted, чекпоинты обработанных
// таблиц на месте, финализация (stats_json + аудит scan_finish) проходит
// даже на отменённом ctx — прогон не остаётся «вечным» running (п. 13).
package scanengine

import (
	"context"
	"iter"
	"testing"

	"github.com/DunchikVlad/zond/internal/connector"
)

// slowCancelConnector отменяет ctx после первой успешной таблицы — имитация
// POST /scans/{id}/stop посреди прогона.
type slowCancelConnector struct {
	*fakeConnector
	cancel  context.CancelFunc
	sampled bool
}

func (c *slowCancelConnector) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	seq, err := c.fakeConnector.Sample(ctx, spec)
	if !c.sampled {
		c.sampled = true
		c.cancel() // stop после первой таблицы
	}
	return seq, err
}

func TestScanInterruptedByContextCancel(t *testing.T) {
	eng, st := testEngine(t)
	src := testSource() // две таблицы: users + orders
	ctx, cancel := context.WithCancel(context.Background())
	conn := &slowCancelConnector{fakeConnector: src, cancel: cancel}

	rep, err := eng.ScanWithID(ctx, conn, "fake", "deep", "scan-stop-1")
	if err != nil {
		t.Fatalf("ScanWithID: %v", err)
	}
	if rep.Status != "interrupted" {
		t.Fatalf("ожидался interrupted, получено %q (rep %+v)", rep.Status, rep)
	}
	// финализация прошла несмотря на отменённый ctx: статус persisted,
	// stats_json записан, аудит scan_finish в цепочке
	sc, err := st.GetScan(context.Background(), "scan-stop-1")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if sc.Status != "interrupted" || sc.FinishedAt == nil || sc.StatsJSON == "" {
		t.Fatalf("persisted scan: %+v", sc)
	}
	repA, err := st.AuditVerify(context.Background())
	if err != nil || !repA.OK() {
		t.Fatalf("цепочка аудита: %+v err=%v", repA, err)
	}
}

// ScanWithID использует заданный идентификатор (контракт API: scan_id
// возвращается клиенту до завершения прогона, п. 11.2 POST /scans).
func TestScanWithIDUsesGivenID(t *testing.T) {
	eng, st := testEngine(t)
	rep, err := eng.ScanWithID(context.Background(), testSource(), "fake", "deep", "fixed-id-1")
	if err != nil {
		t.Fatalf("ScanWithID: %v", err)
	}
	if rep.ScanID != "fixed-id-1" {
		t.Fatalf("ScanID: %q", rep.ScanID)
	}
	if _, err := st.GetScan(context.Background(), "fixed-id-1"); err != nil {
		t.Fatalf("прогон с заданным id не найден: %v", err)
	}
}
