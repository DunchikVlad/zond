// Package clickhouse — коннектор ClickHouse (blueprint п. 9), нативный
// протокол через clickhouse-go/v2 (database/sql-интерфейс для простоты
// типизации строк сэмпла). Регистрация по конвенции путей (п. 4).
package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"math"
	"strings"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DunchikVlad/zond/internal/connector"
)

func init() {
	// дубль регистрации — ошибка программирования (конфликт коннекторов)
	if err := connector.Register("clickhouse", func(dsn string) (connector.Connector, error) {
		return Open(dsn)
	}); err != nil {
		panic(err)
	}
}

type chConnector struct{ db *sql.DB }

// Open создаёт коннектор из DSN вида clickhouse://user:pass@host:9000/db.
func Open(dsn string) (connector.Connector, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	return &chConnector{db: db}, nil
}

func (c *chConnector) Ping(ctx context.Context) error { return c.db.PingContext(ctx) }

// ListTables — system.* и materialized-цели (.inner.*) исключаем (п. 9).
func (c *chConnector) ListTables(ctx context.Context) ([]connector.TableRef, error) {
	const q = `SELECT database, name FROM system.tables ` +
		`WHERE database NOT IN ('system','information_schema') AND name NOT LIKE '.inner.%' ` +
		`ORDER BY database, name`
	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connector.TableRef
	for rows.Next() {
		var t connector.TableRef
		if err := rows.Scan(&t.Schema, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetSchema — системная таблица system.columns; нативный тип разворачивается
// (Nullable(T)/LowCardinality(T) → T, FixedString(N) → String) — п. 9.
func (c *chConnector) GetSchema(ctx context.Context, t connector.TableRef) ([]connector.Column, error) {
	const q = `SELECT name, type, position FROM system.columns WHERE database = ? AND table = ? ORDER BY position`
	rows, err := c.db.QueryContext(ctx, q, t.Schema, t.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connector.Column
	for rows.Next() {
		var col connector.Column
		var typ string
		if err := rows.Scan(&col.Name, &typ, &col.Ordinal); err != nil {
			return nil, err
		}
		col.Ordinal-- // CH position 1-based → 0-based Ordinal
		col.NativeType = unwrapCHType(typ)
		out = append(out, col)
	}
	return out, rows.Err()
}

// unwrapCHType снимает Nullable()/LowCardinality(), FixedString(N) → String.
func unwrapCHType(s string) string {
	for {
		switch {
		case strings.HasPrefix(s, "Nullable(") && strings.HasSuffix(s, ")"):
			s = s[len("Nullable(") : len(s)-1]
		case strings.HasPrefix(s, "LowCardinality(") && strings.HasSuffix(s, ")"):
			s = s[len("LowCardinality(") : len(s)-1]
		case strings.HasPrefix(s, "FixedString("):
			return "String"
		default:
			return s
		}
	}
}

func (c *chConnector) CountRows(ctx context.Context, t connector.TableRef) (int64, error) {
	var n int64
	err := c.db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT count() FROM %s.%s", qid(t.Schema), qid(t.Name))).Scan(&n)
	return n, err
}

// Sample стримит случайный сэмпл (ORDER BY rand() — не head-N, п. 5.1).
// Это «медленный» путь без сэмплинг-ключа (п. 9); оптимизация SAMPLE — позже.
func (c *chConnector) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
	cap := spec.MaxRows
	if cap <= 0 {
		cap = 100_000
	}
	var limit int64
	switch spec.Mode {
	case connector.SampleRows:
		limit = int64(math.Max(1, math.Min(spec.Value, float64(cap))))
	default: // SamplePercent: LIMIT count*p/100 (п. 9)
		var total int64
		if err := c.db.QueryRowContext(ctx,
			fmt.Sprintf("SELECT count() FROM %s.%s", qid(spec.Table.Schema), qid(spec.Table.Name))).Scan(&total); err != nil {
			return nil, err
		}
		limit = int64(math.Max(1, math.Min(float64(total)*spec.Value/100.0, float64(cap))))
	}
	cols := "*"
	if len(spec.Columns) > 0 {
		qs := make([]string, len(spec.Columns))
		for i, col := range spec.Columns {
			qs[i] = qid(col)
		}
		cols = strings.Join(qs, ", ")
	}
	q := fmt.Sprintf("SELECT %s FROM %s.%s ORDER BY rand() LIMIT %d",
		cols, qid(spec.Table.Schema), qid(spec.Table.Name), limit)
	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	names, err := rows.Columns()
	if err != nil {
		rows.Close()
		return nil, err
	}
	return func(yield func(connector.Row, error) bool) {
		defer rows.Close()
		for rows.Next() {
			vals := make([]any, len(names))
			ptrs := make([]any, len(names))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				yield(nil, err)
				return
			}
			row := make(connector.Row, len(names))
			for i, name := range names {
				row[name] = vals[i]
			}
			if !yield(row, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, err)
		}
	}, nil
}

func (c *chConnector) Close() error { return c.db.Close() }

// qid квотирует идентификатор backticks-ами (защита от подстановки в имена).
func qid(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
