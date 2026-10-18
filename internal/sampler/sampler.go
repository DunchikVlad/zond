// Package sampler — потоковая сборка пула значений колонки для анализа
// (blueprint п. 5.2, п. 13): дедуп, усечение длинных строк, подсчёт null.
// Память ограничена MaxRows × MaxStringChars — таблица никогда не читается
// целиком в память (blueprint п. 13).
package sampler

import (
	"iter"
	"strconv"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/connector"
)

// Options — ограничения пула (blueprint п. 5.2).
type Options struct {
	MaxRows        int64 // 0 = без лимита (внешний MaxRows SampleSpec уже задан)
	MaxStringChars int   // усечение; 0 = без усечения
	Dedup          bool  // только уникальные значения в анализ
}

// Pool — значения колонки для анализа.
type Pool struct {
	Values  []string
	Nulls   int // пустые/NULL значения
	Total   int // всего строк, дошедших до пула
	Skipped int // неподдерживаемые типы значений
}

// Build стримит строки rows и собирает строковые представления колонки col.
// Ошибка стрима прерывает сборку и возвращается вызывающему (п. 6 blueprint).
func Build(rows iter.Seq2[connector.Row, error], col string, opts Options) (*Pool, error) {
	p := &Pool{}
	var seen map[string]struct{}
	if opts.Dedup {
		seen = make(map[string]struct{})
	}
	for row, err := range rows {
		if err != nil {
			return p, err
		}
		p.Total++
		raw, present := row[col]
		if !present || raw == nil {
			p.Nulls++
			continue
		}
		s, ok := Stringify(raw)
		if !ok {
			p.Skipped++
			continue
		}
		if s == "" {
			p.Nulls++
			continue
		}
		if opts.MaxStringChars > 0 && len(s) > opts.MaxStringChars {
			s = s[:opts.MaxStringChars]
		}
		if seen != nil {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
		}
		p.Values = append(p.Values, s)
		if opts.MaxRows > 0 && int64(len(p.Values)) >= opts.MaxRows {
			break
		}
	}
	return p, nil
}

// Stringify — строковое представление скалярного значения источника.
// ok=false: nil и неподдерживаемые (сложные) типы — не значения для анализа.
func Stringify(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return strings.TrimSpace(x), true
	case []byte:
		return strings.TrimSpace(string(x)), true
	case bool:
		return strconv.FormatBool(x), true
	case time.Time:
		return x.Format(time.RFC3339), true
	case int:
		return strconv.Itoa(x), true
	case int8:
		return strconv.FormatInt(int64(x), 10), true
	case int16:
		return strconv.FormatInt(int64(x), 10), true
	case int32:
		return strconv.FormatInt(int64(x), 10), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case uint:
		return strconv.FormatUint(uint64(x), 10), true
	case uint8:
		return strconv.FormatUint(uint64(x), 10), true
	case uint16:
		return strconv.FormatUint(uint64(x), 10), true
	case uint32:
		return strconv.FormatUint(uint64(x), 10), true
	case uint64:
		return strconv.FormatUint(x, 10), true
	case float32:
		return strconv.FormatFloat(float64(x), 'f', -1, 32), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	default:
		return "", false
	}
}
