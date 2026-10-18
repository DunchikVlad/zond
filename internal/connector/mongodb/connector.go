// Package mongodb — коннектор MongoDB (blueprint п. 8), официальный драйвер
// mongo-driver/v2. Флаттенинг документов → dot-path (см. flatten.go); сэмпл —
// $sample; полиморфные пути → native_type "mixed". Регистрация по конвенции
// путей (blueprint п. 4).
package mongodb

import (
	"context"
	"fmt"
	"iter"
	"time"

	"github.com/DunchikVlad/zond/internal/connector"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

func init() {
	if err := connector.Register("mongodb", func(uri string) (connector.Connector, error) {
		return Open(uri)
	}); err != nil {
		panic(err)
	}
}

// mgoConnector — коннектор MongoDB; readPreference secondaryPreferred (п. 8:
// $sample и чтения не бьют по primary).
type mgoConnector struct {
	client *mongo.Client
}

// Open создаёт коннектор из URI вида mongodb://user:pass@host:27017/db.
// Фактическое подключение ленивое (драйвер), проверяется Ping'ом.
func Open(uri string) (connector.Connector, error) {
	opts := options.Client().
		ApplyURI(uri).
		SetReadPreference(readpref.SecondaryPreferred()).
		SetTimeout(30 * time.Second)
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, fmt.Errorf("mongodb connect: %w", err)
	}
	return &mgoConnector{client: client}, nil
}

func (c *mgoConnector) Ping(ctx context.Context) error {
	return c.client.Ping(ctx, readpref.SecondaryPreferred())
}

// ListTables — коллекции всех БД, кроме системных (admin/local/config) и
// системных коллекций system.* (по аналогии с исключением system.* в CH, п. 9).
func (c *mgoConnector) ListTables(ctx context.Context) ([]connector.TableRef, error) {
	dbs, err := c.client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	var out []connector.TableRef
	for _, db := range dbs {
		if db == "admin" || db == "local" || db == "config" {
			continue
		}
		colls, err := c.client.Database(db).ListCollectionNames(ctx, bson.D{})
		if err != nil {
			return nil, fmt.Errorf("list collections %s: %w", db, err)
		}
		for _, cn := range collNames(colls) {
			out = append(out, connector.TableRef{Schema: db, Name: cn})
		}
	}
	return out, nil
}

// collNames отбрасывает системные коллекции (system.*).
func collNames(names []string) []string {
	out := names[:0]
	for _, n := range names {
		if len(n) >= 7 && n[:7] == "system." {
			continue
		}
		out = append(out, n)
	}
	return out
}

// GetSchema — схема = объединение ключей по сэмплу документов (п. 8:
// полиморфные коллекции). Берём фиксированный разведывательный сэмпл.
func (c *mgoConnector) GetSchema(ctx context.Context, t connector.TableRef) ([]connector.Column, error) {
	docs, err := c.sampleDocs(ctx, t, schemaSampleSize)
	if err != nil {
		return nil, err
	}
	agg := newSchemaAggregator()
	for _, d := range docs {
		agg.addDocument(d)
	}
	cols := agg.schema()
	out := make([]connector.Column, 0, len(cols))
	for i, col := range cols {
		if skipPath(col.name) {
			continue
		}
		out = append(out, connector.Column{
			Name:       col.name,
			NativeType: col.nativeType,
			Ordinal:    i,
		})
	}
	return out, nil
}

// schemaSampleSize — документов для вывода схемы (п. 8: схема по сэмплу).
const schemaSampleSize = 200

func (c *mgoConnector) CountRows(ctx context.Context, t connector.TableRef) (int64, error) {
	// EstimatedDocumentCount быстрый (метаданные), для полиморфных/разреженных
	// коллекций достаточно; точный CountDocuments дорог на больших (п. 8, п. 13.2).
	return c.client.Database(t.Schema).Collection(t.Name).EstimatedDocumentCount(ctx)
}

// Sample стримит случайный сэмпл через агрегацию $sample (п. 8). При percent —
// size = estimated*p/100, cap по MaxRows. Строки флаттенятся в dot-path.
func (c *mgoConnector) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	cap := spec.MaxRows
	if cap <= 0 {
		cap = 100_000
	}
	var size int64
	switch spec.Mode {
	case connector.SampleRows:
		size = int64(clampFloat(spec.Value, 1, float64(cap)))
	default: // SamplePercent: estimatedDocumentCount * p/100 (п. 8)
		total, err := c.CountRows(ctx, spec.Table)
		if err != nil {
			return nil, err
		}
		size = int64(clampFloat(float64(total)*spec.Value/100.0, 1, float64(cap)))
	}
	docs, err := c.sampleDocs(ctx, spec.Table, size)
	if err != nil {
		return nil, err
	}
	return func(yield func(connector.Row, error) bool) {
		for _, d := range docs {
			flat := flattenDocument(d)
			row := make(connector.Row, len(flat))
			for p, vals := range flat {
				if skipPath(p) {
					continue
				}
				// одно значение — скаляр; массив/множество — список значений
				if len(vals) == 1 {
					row[p] = vals[0]
				} else {
					row[p] = vals
				}
			}
			if !yield(row, nil) {
				return
			}
		}
	}, nil
}

// sampleDocs — $sample size документов коллекции, декодированные в
// map[string]any (BSON→базовые Go-типы драйвером).
func (c *mgoConnector) sampleDocs(ctx context.Context, t connector.TableRef, size int64) ([]map[string]any, error) {
	if size < 1 {
		size = 1
	}
	coll := c.client.Database(t.Schema).Collection(t.Name)
	pipeline := mongo.Pipeline{{{Key: "$sample", Value: bson.D{{Key: "size", Value: size}}}}}
	cur, err := coll.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("sample %s.%s: %w", t.Schema, t.Name, err)
	}
	defer cur.Close(ctx)
	var out []map[string]any
	for cur.Next(ctx) {
		var doc map[string]any
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, doc)
	}
	return out, cur.Err()
}

func (c *mgoConnector) Close() error {
	return c.client.Disconnect(context.Background())
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
