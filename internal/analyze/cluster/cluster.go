// Package cluster — кластеризация колонок по отпечатку fingerprint.FeatureSet
// (blueprint п. 7.6): объединение при совпадении нативного типа и ≥similarity
// остальных признаков; представитель — первая по порядку колонка скана, её
// вердикт распространяется на последующие члены кластера
// (evidence.cluster_propagated=true на стороне движка). Транзитивное
// замыкание ограничено maxSize: полный кластер не пополняется — новая колонка
// начинает отдельный кластер (дробление, упрощение см. ADR-impl-stage-4).
package cluster

import (
	"fmt"

	"github.com/DunchikVlad/zond/internal/fingerprint"
)

// VerdictView — распространяемый вердикт представителя кластера.
type VerdictView struct {
	Label        string
	Confidence   float64
	Layer        string
	ReviewStatus string
}

// entry — один кластер (представитель + счётчик членов + вердикт).
type entry struct {
	id      string
	feat    fingerprint.FeatureSet
	members int
	verdict *VerdictView
}

// Clusterer группирует колонки одного скана. Не потокобезопасен — движок
// обрабатывает колонки последовательно.
type Clusterer struct {
	similarity float64
	maxSize    int
	entries    []*entry // в порядке регистрации (детерминизм)
}

// New создаёт кластеризатор; similarity в (0,1] (default 0.8), maxSize > 0
// (default 100) — blueprint п. 7.6.
func New(similarity float64, maxSize int) *Clusterer {
	if similarity <= 0 || similarity > 1 {
		similarity = 0.8
	}
	if maxSize <= 0 {
		maxSize = 100
	}
	return &Clusterer{similarity: similarity, maxSize: maxSize}
}

// Find ищет подходящий НЕПОЛНЫЙ кластер для отпечатка. Колонки с нестабильным
// типом (Mongo "mixed", п. 8) в кластеризацию не включаются — (false).
func (c *Clusterer) Find(f fingerprint.FeatureSet) (string, bool) {
	if f.NativeType == "" || f.NativeType == "mixed" {
		return "", false
	}
	for _, e := range c.entries {
		if e.members >= c.maxSize {
			continue // замыкание ограничено (п. 7.6)
		}
		if fingerprint.Similarity(e.feat, f) >= c.similarity {
			return e.id, true
		}
	}
	return "", false
}

// Register добавляет колонку как представителя нового кластера; возвращает
// его id. При коллизии (дробление полного кластера) id получает суффикс #n.
func (c *Clusterer) Register(f fingerprint.FeatureSet) string {
	base := fingerprint.ID(f)
	id := base
	for n := 2; c.exists(id); n++ {
		id = fmt.Sprintf("%s#%d", base, n)
	}
	c.entries = append(c.entries, &entry{id: id, feat: f, members: 1})
	return id
}

// Attach увеличивает число членов кластера (колонка встала в кластер, чей
// представитель ещё не классифицирован).
func (c *Clusterer) Attach(id string) {
	for _, e := range c.entries {
		if e.id == id {
			e.members++
			return
		}
	}
}

// SetVerdict сохраняет вердикт представителя для распространения (п. 7.6).
func (c *Clusterer) SetVerdict(id string, v VerdictView) {
	for _, e := range c.entries {
		if e.id == id {
			e.verdict = &v
			return
		}
	}
}

// Verdict возвращает вердикт кластера, если представитель уже классифицирован.
func (c *Clusterer) Verdict(id string) (VerdictView, bool) {
	for _, e := range c.entries {
		if e.id == id && e.verdict != nil {
			return *e.verdict, true
		}
	}
	return VerdictView{}, false
}

func (c *Clusterer) exists(id string) bool {
	for _, e := range c.entries {
		if e.id == id {
			return true
		}
	}
	return false
}
