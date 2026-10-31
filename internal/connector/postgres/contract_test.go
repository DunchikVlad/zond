// Контрактные тесты коннектора PostgreSQL (blueprint п. 16.2).
// Запускаются через conftest.RunConformance с testcontainers.
package postgres

import (
	"context"
	"testing"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/connector/conftest"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		Env:          map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "testdb"},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor:   wait.ForLog("database system is ready to accept connections"),
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	t.Cleanup(func() { ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	dsn := "postgres://postgres:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	conn, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Фикстура: таблица users с email, phone, inn, nullable-полем.
	_, err = conn.(*pgConnector).db.ExecContext(ctx, `
		CREATE TABLE public.users (
			id serial PRIMARY KEY,
			email varchar(255) NOT NULL,
			phone varchar(50),
			inn varchar(12),
			created_at timestamptz DEFAULT now()
		)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	_, err = conn.(*pgConnector).db.ExecContext(ctx, `
		INSERT INTO public.users (email, phone, inn) VALUES
		('ivan@example.com', '+7 999 123-45-67', '7707083893'),
		('petr@test.io', '89991234568', '5001007321'),
		('anna@mail.ru', NULL, NULL)`)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	conftest.RunConformance(t, conftest.Harness{
		Name: "postgresql",
		Connect: func(t *testing.T) connector.Connector {
			return conn
		},
		Table:          connector.TableRef{Schema: "public", Name: "users"},
		WantSchema:     map[string]string{"email": "varchar", "phone": "varchar", "inn": "varchar"},
		RowCount:       3,
		StringColumn:   "email",
		NullableColumn: "phone",
	})
}
