// Package mongodb — коннектор MongoDB (blueprint п. 8).
//
// Флаттенинг: вложенные документы → dot-path (address.city); массивы скаляров
// → одна логическая колонка tags[] (до K элементов на документ, общий пул);
// массивы документов → items[].field, глубина ≤ maxDepth; дальше — «...».
// Полиморфные пути (≥2 типов в >20% документов) → native_type "mixed".
// _id по умолчанию не классифицируется (blueprint п. 8, skip: ["_id"]).
package mongodb

import (
	"fmt"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	// maxDepth — предел рекурсии флаттенинга (blueprint п. 8: глубина ≤ 5).
	maxDepth = 5
	// arrayLimit — макс. элементов массива в пул сэмпла на документ (K=5, п. 8).
	arrayLimit = 5
	// mixedThreshold — доля документов с ≥2 типами пути, чтобы путь стал mixed.
	mixedThreshold = 0.20
)

// pathInfo — агрегированная статистика по одному логическому пути (колонке).
type pathInfo struct {
	// typeCounts — счётчик BSON-классов значений пути по документам.
	typeCounts map[string]int
	// docs — число документов, где путь встретился (включая null).
	docs int
}

// schemaAggregator собирает объединённую схему коллекции по сэмплу документов
// (blueprint п. 8: полиморфные коллекции — объединение ключей).
type schemaAggregator struct {
	paths map[string]*pathInfo
	total int // всего документов в сэмпле
}

func newSchemaAggregator() *schemaAggregator {
	return &schemaAggregator{paths: make(map[string]*pathInfo)}
}

// bsonType — строковый класс значения по BSON (blueprint п. 8 «Типизация путей»).
// objectId/uuid ведут к кандидату IDENTIFIER на слое meta (там словарь имён).
func bsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "bool"
	case int, int32, int64, float32, float64:
		return "number" // decimal/int — один класс для классификации
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		// time.Time, primitive.ObjectID, primitive.Binary (UUID) и прочие
		// драйверные типы, не покрытые явными ветками. Вложенные документы и
		// массивы сюда попадать не должны: sampleDocs нормализует bson.D/bson.A
		// к map[string]any/[]any (type switch не совпадает с именованными типами).
		return "string"
	}
}

// normalize рекурсивно приводит драйверные BSON-типы к базовым Go-типам:
// bson.D → map[string]any, bson.A → []any. Без этого вложенные документы
// и массивы проскакивали в default-ветки bsonType/flattenInto (type switch
// по map[string]any/[]any не совпадает с именованными типами bson.D/bson.A)
// и схема вырождалась в top-level пути — поймано conftest в CI (п. 16.2).
func normalize(v any) any {
	switch t := v.(type) {
	case bson.D:
		m := make(map[string]any, len(t))
		for _, e := range t {
			m[e.Key] = normalize(e.Value)
		}
		return m
	case bson.A:
		s := make([]any, len(t))
		for i, el := range t {
			s[i] = normalize(el)
		}
		return s
	case map[string]any:
		for k, el := range t {
			t[k] = normalize(el)
		}
		return t
	case []any:
		for i, el := range t {
			t[i] = normalize(el)
		}
		return t
	default:
		return v
	}
}

// flattenDocument раскладывает один документ в плоские пути и их значения.
// Ключи результата — dot-path (blueprint п. 8). Массивы → путь с суффиксом []
// (tags[], items[].field); значения массива склеиваются в общий пул (K=5).
//
// Возвращает map[path][]values — для пула сэмпла и статистики типов.
func flattenDocument(doc map[string]any) map[string][]any {
	out := make(map[string][]any)
	flattenInto(doc, "", 0, out)
	return out
}

// flattenInto рекурсивно добавляет в out пары путь→значения.
func flattenInto(v any, prefix string, depth int, out map[string][]any) {
	if depth >= maxDepth {
		// за пределом глубины — сворачиваем в «...» (blueprint п. 8: FREE_TEXT
		// + pending на уровне вердикта; здесь — единый путь-терминатор)
		if prefix != "" {
			out[prefix+"..."] = append(out[prefix+"..."], summarizeDeep(v))
		}
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // детерминированный порядок путей
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flattenInto(t[k], p, depth+1, out)
		}
	case []any:
		// массив: до arrayLimit элементов; скаляры → path[], документы →
		// рекурсия с тем же путём+[] (items[].field) — п. 8.
		n := len(t)
		if n > arrayLimit {
			n = arrayLimit
		}
		for i := 0; i < n; i++ {
			el := t[i]
			switch el.(type) {
			case map[string]any:
				flattenInto(el, prefix+"[]", depth+1, out)
			case []any:
				// вложенный массив — сворачиваем в путь[]...
				out[prefix+"[]..."] = append(out[prefix+"[]..."], summarizeDeep(el))
			default:
				out[prefix+"[]"] = append(out[prefix+"[]"], el)
			}
		}
	default:
		out[prefix] = append(out[prefix], t)
	}
}

// summarizeDeep — компактное строковое представление глубокого значения
// для пути-терминатора «...» (не для LLM напрямую, маскируется позже).
func summarizeDeep(v any) string {
	return fmt.Sprintf("%v", v)
}

// addDocument учитывает один документ сэмпла в агрегированной схеме.
// Отсутствующее поле не учитывается (blueprint п. 8: → null в пуле при сэмпле).
func (a *schemaAggregator) addDocument(doc map[string]any) {
	a.total++
	flat := flattenDocument(doc)
	// типы пути считаем по документу, а не по числу значений (массив даёт
	// несколько значений одного пути в одном документе)
	seen := make(map[string]map[string]bool)
	for p, vals := range flat {
		for _, v := range vals {
			typ := bsonType(v)
			if seen[p] == nil {
				seen[p] = make(map[string]bool)
			}
			seen[p][typ] = true
		}
	}
	for p, types := range seen {
		pi := a.paths[p]
		if pi == nil {
			pi = &pathInfo{typeCounts: make(map[string]int)}
			a.paths[p] = pi
		}
		pi.docs++
		for typ := range types {
			pi.typeCounts[typ]++
		}
	}
}

// column — выходная колонка схемы (внутреннее представление до маппинга
// в connector.Column).
type column struct {
	name       string
	nativeType string // string|number|bool|null|object|array|mixed
	mixedTypes []string
}

// schema вычисляет итоговые колонки: тип пути — доминирующий BSON-класс;
// ≥2 типов в >20% документов, где путь встретился, → "mixed" (blueprint п. 8).
func (a *schemaAggregator) schema() []column {
	cols := make([]column, 0, len(a.paths))
	for p, pi := range a.paths {
		// доминирующий тип по документам
		dom, domN := "", -1
		types := make([]string, 0, len(pi.typeCounts))
		for typ, n := range pi.typeCounts {
			types = append(types, typ)
			if n > domN || (n == domN && typ < dom) {
				dom, domN = typ, n
			}
		}
		sort.Strings(types)
		c := column{name: p, nativeType: dom}
		// нестабильный тип: ≥2 типов, каждый из которых в >20% документов
		if len(types) >= 2 {
			over := 0
			for _, typ := range types {
				if float64(pi.typeCounts[typ])/float64(pi.docs) > mixedThreshold {
					over++
				}
			}
			if over >= 2 {
				c.nativeType = "mixed"
				c.mixedTypes = types
			}
		}
		cols = append(cols, c)
	}
	sort.Slice(cols, func(i, j int) bool { return cols[i].name < cols[j].name })
	return cols
}

// skipPath — пути, исключаемые из классификации по умолчанию (blueprint п. 8:
// _id). Полный список берётся из конфига сканирования, здесь — встроенный
// минимум.
func skipPath(p string) bool {
	base := p
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base == "_id"
}
