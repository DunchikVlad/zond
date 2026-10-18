package meta

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/verdict"
)

func testAnalyzer() *Analyzer {
	return New(map[string][]string{
		"EMAIL":  {"email", "e-mail", "почта"},
		"TAX_ID": {"inn", "инн"},
	})
}

func TestByNameDictionary(t *testing.T) {
	a := testAnalyzer()
	cases := []struct {
		col   string
		label verdict.Label
		conf  float64
	}{
		{"user_email", "EMAIL", 0.85},
		{"EMAIL", "EMAIL", 0.85},
		{"электронная_почта", "EMAIL", 0.85},
		{"client_inn", "TAX_ID", 0.85},
		{"ИНН", "TAX_ID", 0.85},
	}
	for _, c := range cases {
		l, conf, ok := a.ByName(c.col)
		if !ok || l != c.label || conf != c.conf {
			t.Errorf("ByName(%q) = %v,%v,%v; ожидалось %v,%v", c.col, l, conf, ok, c.label, c.conf)
		}
	}
}

func TestByNameRegexFallback(t *testing.T) {
	a := testAnalyzer()
	cases := []struct {
		col   string
		label verdict.Label
	}{
		{"phone_number", "PHONE"},
		{"home_tel", "PHONE"},
		{"мобильный_телефон", "PHONE"},
		{"card_holder", "CARD_NUMBER"},
		{"pan", "CARD_NUMBER"},
		{"passport_num", "PASSPORT_ID"},
		{"snils_id", "SNILS"},
	}
	for _, c := range cases {
		l, conf, ok := a.ByName(c.col)
		if !ok || l != c.label || conf != 0.60 {
			t.Errorf("ByName(%q) = %v,%v,%v; ожидался regex-fallback %v @0.60", c.col, l, conf, ok, c.label)
		}
	}
}

func TestByNameNoFalsePositives(t *testing.T) {
	a := testAnalyzer()
	// "hotel" содержит "tel", но токен не совпадает; словарь не должен стрелять
	for _, col := range []string{"hotel_name", "internal_notes", "amount_total", "created_dt"} {
		if _, _, ok := a.ByName(col); ok {
			t.Errorf("ложное срабатывание на %q", col)
		}
	}
}

func TestDictionaryWinsOverRegex(t *testing.T) {
	a := testAnalyzer()
	l, conf, ok := a.ByName("backup_email")
	if !ok || l != "EMAIL" || conf != 0.85 {
		t.Fatalf("словарь должен иметь приоритет: %v %v %v", l, conf, ok)
	}
}
