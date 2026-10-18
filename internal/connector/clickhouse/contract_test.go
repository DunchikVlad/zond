package clickhouse

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/testcontainers/testcontainers-go"
	tch "github.com/testcontainers/testcontainers-go/modules/clickhouse"
)

// Интеграционный тест коннектора против реального ClickHouse в контейнере
// (blueprint п. 16.2; полный conftest.RunConformance — этап 2).
// Без Docker тест скипается: локально прогон в CI (ubuntu + Docker).

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
	factory, ok := connector.Lookup("clickhouse")
	if !ok {
		t.Fatal("коннектор clickhouse не зарегистрирован")
	}
	conn, err := factory(dsn)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	defer conn.Close()
	waitReady(t, conn)

	exec := func(q string) {
		t.Helper()
		if _, err := conn.(*chConnector).db.ExecContext(ctx, q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`CREATE TABLE testdb.users (
		email String,
		phone Nullable(String),
		inn LowCardinality(String),
		amount Int64
	) ENGINE = Memory`)
	exec(`INSERT INTO testdb.users VALUES
		('ivan@example.com', '+7 999 123-45-67', '7707083893', 100),
		('petr@test.io', NULL, '5001007321', 200)`)

	tables, err := conn.ListTables(ctx)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	if !slices.Contains(tables, connector.TableRef{Schema: "testdb", Name: "users"}) {
		t.Fatalf("users не найдена: %v", tables)
	}
	for _, tb := range tables {
		if tb.Schema == "system" {
			t.Fatalf("system-таблицы должны быть исключены: %v", tables)
		}
	}

	schema, err := conn.GetSchema(ctx, connector.TableRef{Schema: "testdb", Name: "users"})
	if err != nil {
		t.Fatalf("GetSchema: %v", err)
	}
	types := map[string]string{}
	for _, c := range schema {
		types[c.Name] = c.NativeType
	}
	want := map[string]string{"email": "String", "phone": "String", "inn": "String", "amount": "Int64"}
	for col, typ := range want {
		if types[col] != typ {
			t.Fatalf("колонка %s: тип %q, ожидался %q (все: %v)", col, types[col], typ, types)
		}
	}

	n, err := conn.CountRows(ctx, connector.TableRef{Schema: "testdb", Name: "users"})
	if err != nil || n != 2 {
		t.Fatalf("CountRows: n=%d err=%v", n, err)
	}

	seq, err := conn.Sample(ctx, connector.SampleSpec{
		Table:   connector.TableRef{Schema: "testdb", Name: "users"},
		Mode:    connector.SampleRows,
		Value:   10,
		Columns: []string{"email", "phone"},
		MaxRows: 100,
	})
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	var emails []string
	var phones int
	for row, err := range seq {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
		if s, ok := row["email"].(string); ok {
			emails = append(emails, s)
		}
		if row["phone"] != nil {
			phones++
		}
	}
	if len(emails) != 2 || !slices.Contains(emails, "ivan@example.com") {
		t.Fatalf("сэмпл email неверен: %v", emails)
	}
	if phones != 1 {
		t.Fatalf("NULL phone должен приходить как nil: phones=%d", phones)
	}
}

func waitReady(t *testing.T, conn connector.Connector) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := conn.Ping(context.Background()); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ClickHouse не поднялся за 60с")
		}
		time.Sleep(500 * time.Millisecond)
	}
}
