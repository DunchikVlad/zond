package mongodb

import (
	"reflect"
	"sort"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Эталонные кейсы флаттенинга по blueprint п. 8.

func TestFlattenScalarFields(t *testing.T) {
	doc := map[string]any{
		"email":  "ivan@example.com",
		"amount": 100,
		"active": true,
		"note":   nil,
	}
	got := flattenDocument(doc)
	want := map[string][]any{
		"email":  {"ivan@example.com"},
		"amount": {100},
		"active": {true},
		"note":   {nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("flatten:\n got %v\nwant %v", got, want)
	}
}

func TestFlattenNestedDotPath(t *testing.T) {
	doc := map[string]any{
		"address": map[string]any{
			"city": "Moscow",
			"geo":  map[string]any{"lat": 55.7, "lon": 37.6},
			"zip":  "101000",
		},
		"name": "Ivan",
	}
	got := flattenDocument(doc)
	for _, p := range []string{"address.city", "address.geo.lat", "address.geo.lon", "address.zip", "name"} {
		if _, ok := got[p]; !ok {
			t.Fatalf("ожидался путь %q, есть: %v", p, keysOf(got))
		}
	}
	if got["address.city"][0] != "Moscow" {
		t.Fatalf("address.city = %v", got["address.city"])
	}
}

func TestFlattenScalarArray(t *testing.T) {
	doc := map[string]any{"tags": []any{"a", "b", "c"}}
	got := flattenDocument(doc)
	vals, ok := got["tags[]"]
	if !ok {
		t.Fatalf("ожидался путь tags[], есть: %v", keysOf(got))
	}
	if !reflect.DeepEqual(vals, []any{"a", "b", "c"}) {
		t.Fatalf("tags[] = %v", vals)
	}
}

func TestFlattenArrayLimit(t *testing.T) {
	doc := map[string]any{"tags": []any{"1", "2", "3", "4", "5", "6", "7"}}
	got := flattenDocument(doc)
	if n := len(got["tags[]"]); n != arrayLimit {
		t.Fatalf("массив должен урезаться до K=%d, получено %d", arrayLimit, n)
	}
}

func TestFlattenArrayOfDocuments(t *testing.T) {
	doc := map[string]any{
		"items": []any{
			map[string]any{"sku": "A1", "qty": 2},
			map[string]any{"sku": "B2", "qty": 3},
		},
	}
	got := flattenDocument(doc)
	if !reflect.DeepEqual(got["items[].sku"], []any{"A1", "B2"}) {
		t.Fatalf("items[].sku = %v", got["items[].sku"])
	}
	if !reflect.DeepEqual(got["items[].qty"], []any{2, 3}) {
		t.Fatalf("items[].qty = %v", got["items[].qty"])
	}
}

func TestFlattenDepthTerminator(t *testing.T) {
	// строим документ глубже maxDepth
	deep := map[string]any{"leaf": "x"}
	for i := 0; i < maxDepth+2; i++ {
		deep = map[string]any{"n": deep}
	}
	got := flattenDocument(deep)
	foundTerminator := false
	for p := range got {
		if hasTerminator(p) {
			foundTerminator = true
		}
	}
	if !foundTerminator {
		t.Fatalf("на глубине >%d ожидался путь-терминатор «...», есть: %v", maxDepth, keysOf(got))
	}
}

func hasTerminator(p string) bool {
	return len(p) >= 3 && p[len(p)-3:] == "..."
}

func keysOf(m map[string][]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Полиморфная коллекция: схема — объединение ключей, нестабильный тип → mixed.

func TestSchemaUnionKeys(t *testing.T) {
	agg := newSchemaAggregator()
	agg.addDocument(map[string]any{"a": "x", "b": 1})
	agg.addDocument(map[string]any{"a": "y", "c": true})
	cols := agg.schema()
	names := map[string]bool{}
	for _, c := range cols {
		names[c.name] = true
	}
	for _, p := range []string{"a", "b", "c"} {
		if !names[p] {
			t.Fatalf("ожидался путь %q в объединении, есть: %v", p, names)
		}
	}
}

func TestSchemaStableType(t *testing.T) {
	agg := newSchemaAggregator()
	for i := 0; i < 10; i++ {
		agg.addDocument(map[string]any{"email": "e@example.com"})
	}
	cols := agg.schema()
	if len(cols) != 1 || cols[0].nativeType != "string" {
		t.Fatalf("стабильный путь: %+v", cols)
	}
}

func TestSchemaMixedType(t *testing.T) {
	agg := newSchemaAggregator()
	// путь p: в 10 документах string и number поровну (>20% каждый) → mixed
	for i := 0; i < 5; i++ {
		agg.addDocument(map[string]any{"p": "s"})
		agg.addDocument(map[string]any{"p": 42})
	}
	cols := agg.schema()
	if len(cols) != 1 {
		t.Fatalf("ожидалась 1 колонка, есть: %+v", cols)
	}
	if cols[0].nativeType != "mixed" {
		t.Fatalf("нестабильный тип должен быть mixed, получено %q", cols[0].nativeType)
	}
	if !reflect.DeepEqual(cols[0].mixedTypes, []string{"number", "string"}) {
		t.Fatalf("mixedTypes = %v", cols[0].mixedTypes)
	}
}

func TestSchemaRareTypeNotMixed(t *testing.T) {
	agg := newSchemaAggregator()
	// number в 9 из 10 (90%), string в 1 из 10 (10% ≤ 20%) → доминирует number
	for i := 0; i < 9; i++ {
		agg.addDocument(map[string]any{"p": 1})
	}
	agg.addDocument(map[string]any{"p": "s"})
	cols := agg.schema()
	if cols[0].nativeType != "number" {
		t.Fatalf("редкий тип не должен делать путь mixed, получено %q", cols[0].nativeType)
	}
}

func TestSkipPathID(t *testing.T) {
	for _, p := range []string{"_id", "_id.$oid"} {
		if !skipPath(p) {
			t.Fatalf("%q должен исключаться (blueprint п. 8)", p)
		}
	}
	if skipPath("email") {
		t.Fatal("email не должен исключаться")
	}
}

func TestBSONType(t *testing.T) {
	cases := []struct {
		v    any
		want string
	}{
		{nil, "null"},
		{"s", "string"},
		{true, "bool"},
		{1, "number"},
		{int64(2), "number"},
		{3.14, "number"},
		{map[string]any{}, "object"},
		{[]any{}, "array"},
	}
	for _, c := range cases {
		if got := bsonType(c.v); got != c.want {
			t.Fatalf("bsonType(%T) = %q, ожидалось %q", c.v, got, c.want)
		}
	}
}

// FuzzFlattenDocument — устойчивость флаттенера к произвольным вложенным
// структурам (blueprint п. 16.10: BSON-флаттенинг). Инвариант: не паникует,
// глубина путей ограничена, массивы урезаны до K.
func FuzzFlattenDocument(f *testing.F) {
	f.Add("a", "b", int64(1))
	f.Add("x.y", "[]", int64(0))
	f.Add("", "", int64(-1))
	f.Fuzz(func(t *testing.T, k1, k2 string, n int64) {
		doc := map[string]any{
			k1: map[string]any{
				k2: []any{n, k1, map[string]any{k2: n}},
			},
			"plain": n,
		}
		out := flattenDocument(doc) // не должно паниковать
		for p, vals := range out {
			if len(vals) == 0 {
				t.Fatalf("путь %q без значений", p)
			}
		}
	})
}

// TestNormalizeDriverTypes — регрессия: драйвер отдаёт вложенные документы/массивы
// именованными типами bson.D/bson.A, которые type switch на map[string]any/[]any
// не ловил — схема вырождалась в top-level пути (поймано conftest в CI, п. 16.2).
func TestNormalizeDriverTypes(t *testing.T) {
	doc := map[string]any{
		"email": "ivan@example.com",
		"address": bson.D{
			{Key: "city", Value: "Moscow"},
			{Key: "zip", Value: "101000"},
		},
		"tags": bson.A{"vip", "beta"},
		"items": bson.A{
			bson.D{{Key: "sku", Value: "A1"}, {Key: "qty", Value: 2}},
		},
	}
	for k, v := range doc {
		doc[k] = normalize(v)
	}

	got := flattenDocument(doc)
	for _, p := range []string{"address.city", "address.zip", "tags[]", "items[].sku", "items[].qty"} {
		if _, ok := got[p]; !ok {
			t.Fatalf("путь %q не построен: %v", p, keys(got))
		}
	}

	agg := newSchemaAggregator()
	agg.addDocument(doc)
	types := map[string]string{}
	for _, c := range agg.schema() {
		types[c.name] = c.nativeType
	}
	want := map[string]string{
		"email":        "string",
		"address.city": "string",
		"tags[]":       "string",
		"items[].sku":  "string",
		"items[].qty":  "number",
	}
	for p, typ := range want {
		if types[p] != typ {
			t.Fatalf("путь %s: тип %q, ожидался %q (все: %v)", p, types[p], typ, types)
		}
	}
}

func keys(m map[string][]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
