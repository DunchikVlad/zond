// Package drift — дрейф схемы и вердиктов между двумя прогонами одного
// источника (blueprint п. 11.2 GET /api/v1/drift, страница /drift п. 11.3):
// новые/исчезнувшие колонки и смены лейблов/уверенности.
//
// Алгоритм: базовый прогон — последний завершённый до since (или предыдущий
// относительно current), текущий — последний завершённый прогон источника.
// Сравнение по ключу (table_name, path); лейбл — с учётом ручного ревью
// (final_label, если задан).
package drift

import (
	"context"
	"sort"
	"time"

	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// ColumnChange — смена вердикта по колонке (п. 11.2).
type ColumnChange struct {
	Table          string              `json:"table"`
	Path           string              `json:"path"`
	NativeType     string              `json:"native_type"`
	FromLabel      verdict.Label       `json:"from_label"`
	ToLabel        verdict.Label       `json:"to_label"`
	FromConfidence float64             `json:"from_confidence"`
	ToConfidence   float64             `json:"to_confidence"`
	Sensitivity    verdict.Sensitivity `json:"sensitivity"`
}

// ColumnRef — колонка, появившаяся или исчезнувшая между прогонами.
type ColumnRef struct {
	Table      string        `json:"table"`
	Path       string        `json:"path"`
	NativeType string        `json:"native_type"`
	Label      verdict.Label `json:"label"`
}

// Report — дифф двух прогонов источника.
type Report struct {
	Source     string         `json:"source"`
	BaseScanID string         `json:"base_scan_id"`
	CurrScanID string         `json:"curr_scan_id"`
	Added      []ColumnRef    `json:"added"`   // колонки появились в curr
	Removed    []ColumnRef    `json:"removed"` // колонки исчезли из curr
	Changed    []ColumnChange `json:"changed"` // смена лейбла/уверенности
}

// labelOf — эффективный лейбл вердикта: ручной (после ревью) приоритетнее
// автоматического (п. 5.4, п. 11.3 — дрейф смотрит на «текущее» решение).
func labelOf(v verdict.Verdict) verdict.Label {
	if v.FinalLabel != "" {
		return v.FinalLabel
	}
	return v.Label
}

// confidenceDelta — минимальная смена confidence, считающаяся дрейфом
// (меньше — шум сэмплирования; п. 11.3 «смены лейблов/уверенности»).
const confidenceDelta = 0.05

// key — идентичность колонки внутри прогона.
func key(v verdict.Verdict) string { return v.Table + "\x00" + v.Path }

// Compare строит дифф base → curr (оба — списки вердиктов одного источника).
func Compare(baseScanID string, base []verdict.Verdict, currScanID string, curr []verdict.Verdict) *Report {
	rep := &Report{
		Source:     "",
		BaseScanID: baseScanID,
		CurrScanID: currScanID,
		Added:      []ColumnRef{},
		Removed:    []ColumnRef{},
		Changed:    []ColumnChange{},
	}
	bIdx := make(map[string]verdict.Verdict, len(base))
	for _, v := range base {
		bIdx[key(v)] = v
	}
	cIdx := make(map[string]verdict.Verdict, len(curr))
	for _, v := range curr {
		cIdx[key(v)] = v
		b, ok := bIdx[key(v)]
		switch {
		case !ok:
			rep.Added = append(rep.Added, ColumnRef{
				Table: v.Table, Path: v.Path, NativeType: v.NativeType, Label: labelOf(v),
			})
		default:
			bl, cl := labelOf(b), labelOf(v)
			dConf := v.Confidence - b.Confidence
			if dConf < 0 {
				dConf = -dConf
			}
			if bl != cl || dConf >= confidenceDelta {
				rep.Changed = append(rep.Changed, ColumnChange{
					Table: v.Table, Path: v.Path, NativeType: v.NativeType,
					FromLabel: bl, ToLabel: cl,
					FromConfidence: b.Confidence, ToConfidence: v.Confidence,
					Sensitivity: v.Sensitivity,
				})
			}
		}
	}
	for _, v := range base {
		if _, ok := cIdx[key(v)]; !ok {
			rep.Removed = append(rep.Removed, ColumnRef{
				Table: v.Table, Path: v.Path, NativeType: v.NativeType, Label: labelOf(v),
			})
		}
	}
	sort.Slice(rep.Added, func(i, j int) bool {
		if rep.Added[i].Table != rep.Added[j].Table {
			return rep.Added[i].Table < rep.Added[j].Table
		}
		return rep.Added[i].Path < rep.Added[j].Path
	})
	sort.Slice(rep.Removed, func(i, j int) bool {
		if rep.Removed[i].Table != rep.Removed[j].Table {
			return rep.Removed[i].Table < rep.Removed[j].Table
		}
		return rep.Removed[i].Path < rep.Removed[j].Path
	})
	sort.Slice(rep.Changed, func(i, j int) bool {
		if rep.Changed[i].Table != rep.Changed[j].Table {
			return rep.Changed[i].Table < rep.Changed[j].Table
		}
		return rep.Changed[i].Path < rep.Changed[j].Path
	})
	return rep
}

// BetweenLatest — дрейф двух последних завершённых прогонов источника
// (GET /api/v1/drift?source=…&since=…): текущий — свежайший прогон со
// статусом не running; базовый — предыдущий, при заданном since — не старше
// since. ok=false, если пару сравнить нельзя (прогонов меньше двух).
func BetweenLatest(ctx context.Context, st *store.Store, source string, since *time.Time) (*Report, bool, error) {
	scans, _, err := st.ListScans(ctx, store.ScanFilter{Source: source, Limit: store.MaxPageLimit})
	if err != nil {
		return nil, false, err
	}
	var done []store.Scan
	for _, sc := range scans {
		if sc.Status == "running" {
			continue
		}
		if since != nil && sc.StartedAt.Before(*since) {
			continue
		}
		done = append(done, sc)
	}
	if len(done) < 2 {
		return nil, false, nil
	}
	curr, base := done[0], done[1]
	baseV, err := st.ListVerdicts(ctx, base.ID)
	if err != nil {
		return nil, false, err
	}
	currV, err := st.ListVerdicts(ctx, curr.ID)
	if err != nil {
		return nil, false, err
	}
	rep := Compare(base.ID, baseV, curr.ID, currV)
	rep.Source = source
	return rep, true, nil
}
