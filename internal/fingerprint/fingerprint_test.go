package fingerprint

import "testing"

func sampleValues() []string {
	return []string{"+7 *** *** 12 34", "+7 *** *** 56 78", "not-a-phone-at-all"}
}

func TestComputeDeterministic(t *testing.T) {
	a := Compute("String", sampleValues(), 10, 2)
	b := Compute("String", sampleValues(), 10, 2)
	if a != b {
		t.Fatalf("Compute недетерминирован: %+v vs %+v", a, b)
	}
	if a.NativeType != "String" || a.MinLen <= 0 || a.MaxLen < a.MinLen {
		t.Fatalf("базовые признаки неверны: %+v", a)
	}
	if a.DominantClass == "" || a.Prefix2 == "" || a.Suffix2 == "" {
		t.Fatalf("класс/префикс/суффикс не заполнены: %+v", a)
	}
	if a.NullFrac != 0.2 {
		t.Fatalf("NullFrac = %v, ожидалось 0.2", a.NullFrac)
	}
}

func TestValuesHashOrderIndependent(t *testing.T) {
	h1 := ValuesHash([]string{"b", "a", "a", "c"})
	h2 := ValuesHash([]string{"c", "b", "a"})
	if h1 != h2 {
		t.Fatal("ValuesHash зависит от порядка/дублей")
	}
	if ValuesHash([]string{"a"}) == ValuesHash([]string{"b"}) {
		t.Fatal("ValuesHash не различает значения")
	}
}

func TestSimilarity(t *testing.T) {
	base := Compute("String", sampleValues(), 10, 2)
	if s := Similarity(base, base); s != 1 {
		t.Fatalf("Similarity(сам с собой) = %v", s)
	}
	other := base
	other.NativeType = "Int64"
	if s := Similarity(base, other); s != 0 {
		t.Fatalf("разные типы должны давать 0, получено %v", s)
	}
	// меняем префикс/суффикс и доминирующий класс → ≥2 признака расходятся
	diff := base
	diff.Prefix2 = "zz"
	diff.Suffix2 = "zz"
	if s := Similarity(base, diff); s >= 0.9 {
		t.Fatalf("похожие с другим префиксом/суффиксом: %v", s)
	}
}

func TestIDStable(t *testing.T) {
	a := ID(Compute("String", sampleValues(), 10, 2))
	b := ID(Compute("String", sampleValues(), 10, 2))
	if a != b || len(a) != 16 {
		t.Fatalf("ID нестабилен/неожиданной длины: %q vs %q", a, b)
	}
}

func TestDominantClass(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"digits", []string{"12345", "67890"}, ClassDigit},
		{"alpha", []string{"ivan", "petr"}, ClassAlpha},
		{"mixed", []string{"ab12", "cd34"}, ClassMixed},
	}
	for _, c := range cases {
		f := Compute("String", c.values, len(c.values), 0)
		if f.DominantClass != c.want {
			t.Errorf("%s: DominantClass=%s, ожидался %s", c.name, f.DominantClass, c.want)
		}
	}
}
