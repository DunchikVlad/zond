// Package postgres — коннектор PostgreSQL (blueprint п. 9, S9-5).
// database/sql через lib/pq (pure Go, нет cgo). Регистрация по конвенции путей (п. 4).
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"math"
	"strings"

	"github.com/DunchikVlad/zond/internal/connector"
	_ "github.com/lib/pq"
)

func init() {
	if err := connector.Register("postgresql", func(dsn string) (connector.Connector, error) {
		return Open(dsn)
	}); err != nil {
		panic(err)
	}
}

type pgConnector struct{ db *sql.DB }

// Open создаёт коннектор из DSN вида postgres://user:pass@host:5432/db?sslmode=disable.
func Open(dsn string) (connector.Connector, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	return &pgConnector{db: db}, nil
}

func (c *pgConnector) Ping(ctx context.Context) error { return c.db.PingContext(ctx) }

// ListTables — системные схемы исключаем (pg_catalog, information_schema).
func (c *pgConnector) ListTables(ctx context.Context) ([]connector.TableRef, error) {
	const q = `SELECT table_schema, table_name FROM information_schema.tables
		WHERE table_type = 'BASE TABLE'
		AND table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY table_schema, table_name`
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

// GetSchema — information_schema.columns; нативный тип разворачивается
// (character varying → varchar, timestamp with time zone → timestamptz).
func (c *pgConnector) GetSchema(ctx context.Context, t connector.TableRef) ([]connector.Column, error) {
	const q = `SELECT column_name, data_type, ordinal_position
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position`
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
		col.Ordinal-- // PG ordinal_position 1-based → 0-based Ordinal
		col.NativeType = unwrapPGType(typ)
		out = append(out, col)
	}
	return out, rows.Err()
}

// unwrapPGType — нормализация нативных типов PostgreSQL.
func unwrapPGType(s string) string {
	switch s {
	case "character varying":
		return "varchar"
	case "timestamp with time zone":
		return "timestamptz"
	case "timestamp without time zone":
		return "timestamp"
	case "double precision":
		return "float8"
	case "boolean":
		return "bool"
	}
	return s
}

func (c *pgConnector) CountRows(ctx context.Context, t connector.TableRef) (int64, error) {
	var n int64
	err := c.db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT count(*) FROM %s.%s", qid(t.Schema), qid(t.Name))).Scan(&n)
	return n, err
}

// Sample стримит случайный сэмпл (ORDER BY random() — не head-N, п. 5.1).
func (c *pgConnector) Sample(ctx context.Context, spec connector.SampleSpec) (iter.Seq2[connector.Row, error], error) {
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
			fmt.Sprintf("SELECT count(*) FROM %s.%s", qid(spec.Table.Schema), qid(spec.Table.Name))).Scan(&total); err != nil {
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
	q := fmt.Sprintf("SELECT %s FROM %s.%s ORDER BY random() LIMIT %d",
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

func (c *pgConnector) Close() error { return c.db.Close() }

// qid квотирует идентификатор двойными кавычками (защита от подстановки).
func qid(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
