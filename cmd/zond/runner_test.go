package main

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/api"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// gateConn — тестовый коннектор с управляемой блокировкой ListTables:
// первый прогон занимает слот max_concurrent_scans до снятия блокировки
// (п. 13.2, max_concurrent_scans).
type gateConn struct {
	release <-chan struct{} // ListTables ждёт закрытия
}

func (c *gateConn) Ping(ctx context.Context) error { return nil }

func (c *gateConn) ListTables(ctx context.Context) ([]connector.TableRef, error) {
	select {
	case <-c.release:
		return nil, nil // пустой источник — прогон завершается done
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *gateConn) GetSchema(ctx context.Context, t connector.TableRef) ([]connector.Column, error) {
	return nil, errors.New("gateConn: таблиц нет")
}
func (c *gateConn) CountRows(ctx context.Context, t connector.TableRef) (int64, error) {
	return 0, nil
}
func (c *gateConn) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	return func(func(connector.Row, error) bool) {}, nil
}
func (c *gateConn) Close() error { return nil }

var registerGateConn = sync.Once{}

// TestRunnerMaxConcurrentScans — семафор max_concurrent_scans источника
// (S8-2, п. 13.2): повторный старт при занятом слоте — 502
// source_unavailable до подключения; слот освобождается по завершении
// прогона — следующий старт проходит.
func TestRunnerMaxConcurrentScans(t *testing.T) {
	release := make(chan struct{})
	registerGateConn.Do(func() {
		if err := connector.Register("test-gated", func(dsn string) (connector.Connector, error) {
			return &gateConn{release: release}, nil
		}); err != nil {
			t.Fatalf("регистрация тестового коннектора: %v", err)
		}
	})
	b := &config.Bundle{
		Connections: &config.Connections{Version: "1", Sources: []config.Source{
			{Name: "gated", Type: "test-gated", DSN: "test://x"}, // лимиты по дефолту: scans=1
		}},
		Detectors: &config.Detectors{},
		Taxonomy:  &config.Taxonomy{},
	}
	st, err := store.Open(t.TempDir() + "/runner.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	r := newEngineRunner(b, st, slog.New(slog.DiscardHandler), false, nil)

	if _, err := r.Start("gated", "", "test"); err != nil {
		t.Fatalf("первый старт: %v", err)
	}
	// Слот занят (первый прогон заблокирован в ListTables): второй старт —
	// отказ 502 source_unavailable (п. 13.2).
	_, err = r.Start("gated", "", "test")
	var unavail *api.SourceUnavailableError
	if !errors.As(err, &unavail) {
		t.Fatalf("второй старт при занятом слоте: ожидался SourceUnavailableError, получено %v", err)
	}

	// Завершаем первый прогон: слот освобождается — следующий старт проходит.
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err = r.Start("gated", "", "test")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("слот не освобождён после завершения прогона: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Дожидаемся завершения последнего прогона (слот освобождается асинхронно).
	deadline = time.Now().Add(3 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.running)
		r.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("прогон не завершился: running=%d", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRunnerScansLimitAboveOne — лимит >1 из конфига: несколько параллельных
// прогонов одного источника допускаются (п. 13.2, max_concurrent_scans: 2).
func TestRunnerScansLimitAboveOne(t *testing.T) {
	release := make(chan struct{})
	registerGateConn.Do(func() {}) // регистрация — в предыдущем тесте (Once)
	b := &config.Bundle{
		Connections: &config.Connections{Version: "1", Sources: []config.Source{
			{Name: "gated", Type: "test-gated", DSN: "test://x", MaxConcurrentScans: 2},
		}},
		Detectors: &config.Detectors{},
		Taxonomy:  &config.Taxonomy{},
	}
	st, err := store.Open(t.TempDir() + "/runner2.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()
	r := newEngineRunner(b, st, slog.New(slog.DiscardHandler), false, nil)

	for i := 0; i < 2; i++ {
		if _, err := r.Start("gated", "", "test"); err != nil {
			t.Fatalf("старт %d при лимите 2: %v", i+1, err)
		}
	}
	_, err = r.Start("gated", "", "test")
	var unavail *api.SourceUnavailableError
	if !errors.As(err, &unavail) {
		t.Fatalf("третий старт при лимите 2: ожидался SourceUnavailableError, получено %v", err)
	}
	close(release)
}
