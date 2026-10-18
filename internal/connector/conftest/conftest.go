// Package conftest — общие контрактные тесты коннекторов (blueprint п. 16.2).
// RunConformance прогоняет один и тот же набор проверок против ClickHouse и
// MongoDB через testcontainers: ListTables/GetSchema/CountRows/Sample на
// идентичных данных дают сопоставимые результаты, соблюдается MaxRows,
// NULL/отсутствующее поле приходит как nil, ошибка одной таблицы не роняет
// ListTables. Конкретная БД подставляет себя через Harness.
package conftest

import (
	"context"
	"testing"

	"github.com/DunchikVlad/zond/internal/connector"
)

// Harness — привязка контрактного набора к конкретной БД.
// Каждый коннектор реализует её в своём интеграционном тесте.
type Harness struct {
	// Name — имя БД для сообщений об ошибках (clickhouse|mongodb).
	Name string
	// Connect поднимает тестовый контейнер, загружает фикстуру Fixture и
	// возвращает готовый коннектор (t.Cleanup останавливает контейнер).
	Connect func(t *testing.T) connector.Connector
	// Table — таблица/коллекция фикстуры (создаётся в Connect).
	Table connector.TableRef
	// WantSchema — ожидаемые колонки/пути фикстуры: имя → нативный тип
	// после разворачивания/флаттенинга. Для Mongo — dot-path.
	WantSchema map[string]string
	// RowCount — число строк/документов в фикстуре.
	RowCount int64
	// StringColumn — колонка/путь со строковым значением, присутствующее во
	// всех строках (проверяется непустым в Sample).
	StringColumn string
	// NullableColumn — колонка/путь, в части строк NULL/отсутствует
	// (проверяется, что приходит как nil, а не роняет сэмпл).
	NullableColumn string
}

// RunConformance выполняет контрактный набор против h.
// Вызывается из интеграционных тестов конкретных коннекторов; без Docker
// скипается в Connect (testcontainers.SkipIfProviderIsNotHealthy).
func RunConformance(t *testing.T, h Harness) {
	t.Helper()
	ctx := context.Background()
	conn := h.Connect(t)
	defer conn.Close()

	t.Run("Ping", func(t *testing.T) {
		if err := conn.Ping(ctx); err != nil {
			t.Fatalf("[%s] Ping: %v", h.Name, err)
		}
	})

	t.Run("ListTables", func(t *testing.T) {
		tables, err := conn.ListTables(ctx)
		if err != nil {
			t.Fatalf("[%s] ListTables: %v", h.Name, err)
		}
		if !containsTable(tables, h.Table) {
			t.Fatalf("[%s] таблица %v не найдена: %v", h.Name, h.Table, tables)
		}
	})

	t.Run("GetSchema", func(t *testing.T) {
		schema, err := conn.GetSchema(ctx, h.Table)
		if err != nil {
			t.Fatalf("[%s] GetSchema: %v", h.Name, err)
		}
		got := map[string]string{}
		for _, c := range schema {
			got[c.Name] = c.NativeType
		}
		for col, wantType := range h.WantSchema {
			if got[col] != wantType {
				t.Fatalf("[%s] колонка %q: тип %q, ожидался %q (все: %v)",
					h.Name, col, got[col], wantType, got)
			}
		}
	})

	t.Run("CountRows", func(t *testing.T) {
		n, err := conn.CountRows(ctx, h.Table)
		if err != nil {
			t.Fatalf("[%s] CountRows: %v", h.Name, err)
		}
		if n != h.RowCount {
			t.Fatalf("[%s] CountRows = %d, ожидалось %d", h.Name, n, h.RowCount)
		}
	})

	t.Run("SampleRespectsMaxRows", func(t *testing.T) {
		seq, err := conn.Sample(ctx, connector.SampleSpec{
			Table: h.Table, Mode: connector.SampleRows, Value: 1000, MaxRows: 1,
		})
		if err != nil {
			t.Fatalf("[%s] Sample: %v", h.Name, err)
		}
		var n int64
		for _, err := range seq {
			if err != nil {
				t.Fatalf("[%s] stream: %v", h.Name, err)
			}
			n++
		}
		if n > 1 {
			t.Fatalf("[%s] MaxRows=1 нарушен: получено %d строк", h.Name, n)
		}
	})

	t.Run("SampleRowsAndNull", func(t *testing.T) {
		seq, err := conn.Sample(ctx, connector.SampleSpec{
			Table:   h.Table,
			Mode:    connector.SampleRows,
			Value:   float64(h.RowCount),
			Columns: nil, // все колонки/пути
			MaxRows: 100,
		})
		if err != nil {
			t.Fatalf("[%s] Sample: %v", h.Name, err)
		}
		var rows, withString, nulls int
		for row, err := range seq {
			if err != nil {
				t.Fatalf("[%s] stream: %v", h.Name, err)
			}
			rows++
			if s, ok := scalarString(row[h.StringColumn]); ok && s != "" {
				withString++
			}
			if isNilOrAbsent(row, h.NullableColumn) {
				nulls++
			}
		}
		if rows != int(h.RowCount) {
			t.Fatalf("[%s] Sample вернул %d строк, ожидалось %d", h.Name, rows, h.RowCount)
		}
		if withString == 0 {
			t.Fatalf("[%s] строковая колонка %q пуста во всех строках", h.Name, h.StringColumn)
		}
		if nulls == 0 {
			t.Fatalf("[%s] ожидались NULL в %q хотя бы в одной строке", h.Name, h.NullableColumn)
		}
	})
}

func containsTable(tables []connector.TableRef, want connector.TableRef) bool {
	for _, tb := range tables {
		if tb == want {
			return true
		}
	}
	return false
}

// scalarString извлекает строку из значения ячейки (скаляр или 1-элементный
// пул массива Mongo).
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case []any:
		if len(t) == 1 {
			if s, ok := t[0].(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

// isNilOrAbsent — NULL/отсутствующее поле приходит как nil (п. 5.1, п. 8).
func isNilOrAbsent(row connector.Row, col string) bool {
	v, ok := row[col]
	return !ok || v == nil
}
