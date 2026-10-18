package mongodb

import (
	"context"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/connector/conftest"
	"github.com/testcontainers/testcontainers-go"
	tmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"
	mongodrv "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Интеграционный тест коннектора против реального MongoDB в контейнере
// (blueprint п. 16.2) + общий контрактный набор conftest.RunConformance.
// Без Docker тест скипается: локально прогон в CI (ubuntu + Docker).

// Фикстура: документы с вложенными объектами, массивами скаляров/документов
// и NULL/отсутствующим полем — покрывает п. 8 (флаттенинг, массивы, union).

func TestMongoDBConnectorIntegration(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()

	ctr, err := tmongo.Run(ctx, "mongo:7")
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	uri, err := ctr.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("uri: %v", err)
	}
	seedFixture(t, ctx, uri)

	conftest.RunConformance(t, conftest.Harness{
		Name:    "mongodb",
		Connect: func(t *testing.T) connector.Connector { return connectAndWait(t, ctx, uri) },
		Table:   connector.TableRef{Schema: "testdb", Name: "users"},
		WantSchema: map[string]string{
			"email":        "string",
			"phone":        "string",
			"address.city": "string",
			"tags[]":       "string",
			"items[].qty":  "number",
			"items[].sku":  "string",
		},
		RowCount:       2,
		StringColumn:   "email",
		NullableColumn: "phone",
	})
}

// seedFixture загружает детерминированную фикстуру через официальный клиент.
func seedFixture(t *testing.T, ctx context.Context, uri string) {
	t.Helper()
	client, err := mongodrv.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	defer func() { _ = client.Disconnect(ctx) }()
	coll := client.Database("testdb").Collection("users")
	docs := []any{
		bson.M{
			"email":   "ivan@example.com",
			"phone":   "+7 999 123-45-67",
			"address": bson.M{"city": "Moscow", "zip": "101000"},
			"tags":    bson.A{"vip", "beta"},
			"items":   bson.A{bson.M{"sku": "A1", "qty": 2}},
		},
		bson.M{
			"email": "petr@test.io",
			// phone отсутствует → nil в пуле (blueprint п. 8)
			"address": bson.M{"city": "Kazan"},
			"tags":    bson.A{"news"},
			"items":   bson.A{bson.M{"sku": "B2", "qty": 5}},
		},
	}
	if _, err := coll.InsertMany(ctx, docs); err != nil {
		t.Fatalf("seed insert: %v", err)
	}
}

func connectAndWait(t *testing.T, ctx context.Context, uri string) connector.Connector {
	t.Helper()
	factory, ok := connector.Lookup("mongodb")
	if !ok {
		t.Fatal("коннектор mongodb не зарегистрирован")
	}
	conn, err := factory(uri)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := conn.Ping(ctx); err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("MongoDB не поднялась за 60с")
		}
		time.Sleep(500 * time.Millisecond)
	}
}
