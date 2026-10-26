// Package connector — SPI коннекторов к БД-источникам (blueprint п. 5.1).
// Новая БД подключается по конвенции путей без правки ядра (blueprint п. 4):
// реализация internal/connector/<db> с регистрацией в init().
package connector

import (
	"context"
	"iter"
	"strings"
)

// TableRef — таблица/коллекция источника.
type TableRef struct {
	Schema string
	Name   string
}

var qualifiedNameEscaper = strings.NewReplacer(`\`, `\\`, `.`, `\.`)

// QualifiedName — устойчивый идентификатор schema.table для store и API.
// Обратная косая черта и точка внутри компонентов экранируются, чтобы разные
// пары Schema/Name не давали одинаковый ключ. Драйверы получают исходный TableRef.
func (t TableRef) QualifiedName() string {
	return qualifiedNameEscaper.Replace(t.Schema) + "." + qualifiedNameEscaper.Replace(t.Name)
}

// Column — колонка/путь источника.
type Column struct {
	Name       string
	NativeType string
	Ordinal    int
}

// Row — строка сэмпла; ключ — имя колонки / dot-path поля (blueprint п. 8).
type Row map[string]any

// SampleMode — режим сэмплирования.
type SampleMode int

const (
	SampleRows    SampleMode = iota // ровно N строк
	SamplePercent                   // p% (0 < p <= 100)
)

// SampleSpec — спецификация сэмпла (blueprint п. 5.1).
type SampleSpec struct {
	Table   TableRef
	Mode    SampleMode
	Value   float64
	Columns []string // nil = все
	MaxRows int64    // жёсткий предохранитель, по умолчанию 100_000
}

// Connector — единый интерфейс источника данных.
// Sample стримит строки; итератор завершается по EOF, ошибке или cancel.
type Connector interface {
	Ping(ctx context.Context) error
	ListTables(ctx context.Context) ([]TableRef, error)
	GetSchema(ctx context.Context, t TableRef) ([]Column, error)
	CountRows(ctx context.Context, t TableRef) (int64, error)
	Sample(ctx context.Context, spec SampleSpec) (iter.Seq2[Row, error], error)
	Close() error
}
