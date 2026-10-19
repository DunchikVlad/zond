package cluster

import (
	"strings"
	"testing"

	"github.com/DunchikVlad/zond/internal/fingerprint"
)

func feat(nativeType string) fingerprint.FeatureSet {
	return fingerprint.FeatureSet{
		NativeType:    nativeType,
		DominantClass: fingerprint.ClassDigit,
		MinLen:        10, MaxLen: 12, AvgLen: 11,
		NullFrac: 0, UniqueFrac: 1, Entropy: 3.5,
		Prefix2: "77", Suffix2: "89",
	}
}

func TestRegisterAndFind(t *testing.T) {
	c := New(0.8, 100)
	id1 := c.Register(feat("String"))
	id2, ok := c.Find(feat("String"))
	if !ok || id2 != id1 {
		t.Fatalf("Find не вернул кластер представителя: id=%s ok=%v", id2, ok)
	}
	if _, ok := c.Find(feat("Int64")); ok {
		t.Fatal("колонка с другим типом не должна попадать в кластер")
	}
}

func TestMixedNotClustered(t *testing.T) {
	c := New(0.8, 100)
	if _, ok := c.Find(feat("mixed")); ok {
		t.Fatal("mixed-типы не кластеризуются (п. 7.6)")
	}
	if _, ok := c.Find(feat("")); ok {
		t.Fatal("пустой тип не кластеризуется")
	}
}

func TestMaxSizeSplits(t *testing.T) {
	c := New(0.8, 1) // размер 1: представитель занял слот
	first := c.Register(feat("String"))
	if _, ok := c.Find(feat("String")); ok {
		t.Fatal("полный кластер не должен пополняться (п. 7.6)")
	}
	second := c.Register(feat("String")) // дробление
	if second == first || !strings.HasPrefix(second, first+"#") {
		t.Fatalf("дробление должно давать суффикс #n: %s vs %s", first, second)
	}
}

func TestVerdictPropagation(t *testing.T) {
	c := New(0.8, 100)
	id := c.Register(feat("String"))
	if _, ok := c.Verdict(id); ok {
		t.Fatal("вердикта ещё нет")
	}
	c.Attach(id) // член кластера до вердикта представителя
	c.SetVerdict(id, VerdictView{Label: "PHONE", Confidence: 0.9, Layer: "llm", ReviewStatus: "auto_accepted"})
	v, ok := c.Verdict(id)
	if !ok || v.Label != "PHONE" || v.Confidence != 0.9 {
		t.Fatalf("вердикт представителя не сохранился: %+v ok=%v", v, ok)
	}
}

func TestDefaults(t *testing.T) {
	c := New(0, 0)
	if c.similarity != 0.8 || c.maxSize != 100 {
		t.Fatalf("дефолты неверны: %v %v", c.similarity, c.maxSize)
	}
}
