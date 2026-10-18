package clickhouse

import (
	"context"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/connector/conftest"
	"github.com/testcontainers/testcontainers-go"
	tch "github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

// Интеграционный тест коннектора против реального ClickHouse в контейнере +
// общий контрактный набор conftest.RunConformance (blueprint п. 16.2).
// Без Docker тест скипается: локально прогон в CI (ubuntu + Docker).

// Фикстура соответствует MongoDB (conftest): email во всех строках, phone —
// NULL в части строк; типы после unwrap — п. 9.
func TestClickHouseConnectorIntegration(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()

	ctr, err := tch.Run(ctx, "clickhouse/clickhouse-server:24.8-alpine",
		tch.WithDatabase("testdb"),
		tch.WithUsername("zond"),
		tch.WithPassword("zond"),
	)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	dsn, err := ctr.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}

	var conn *chConnector
	conftest.RunConformance(t, conftest.Harness{
		Name: "clickhouse",
		Connect: func(t *testing.T) connector.Connector {
			conn = connectAndSeed(t, ctx, dsn)
			return conn
		},
		Table: connector.TableRef{Schema: "testdb", Name: "users"},
		WantSchema: map[string]string{
			"email": "String",
			"phone": "String", // Nullable(String) → String (п. 9)
			"inn":   "String", // LowCardinality(String) → String
		},
		RowCount:       2,
		StringColumn:   "email",
		NullableColumn: "phone",
	})
}

// connectAndSeed поднимает коннектор, ждёт готовности и загружает фикстуру.
func connectAndSeed(t *testing.T, ctx context.Context, dsn string) *chConnector {
	t.Helper()
	factory, ok := connector.Lookup("clickhouse")
	if !ok {
		t.Fatal("коннектор clickhouse не зарегистрирован")
	}
	c, err := factory(dsn)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ch, ok := c.(*chConnector)
	if !ok {
		t.Fatalf("ожидался *chConnector, получено %T", c)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := ch.Ping(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ClickHouse не поднялся за 60с")
		}
		time.Sleep(500 * time.Millisecond)
	}
	exec := func(q string) {
		t.Helper()
		if _, err := ch.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`CREATE TABLE testdb.users (
		email String,
		phone Nullable(String),
		inn LowCardinality(String)
	) ENGINE = Memory`)
	exec(`INSERT INTO testdb.users VALUES
		('ivan@example.com', '+7 999 123-45-67', '7707083893'),
		('petr@test.io', NULL, '5001007321')`)
	return ch
}
