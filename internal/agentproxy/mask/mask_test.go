package mask

import "testing"

// Табличные тесты маскировщика (blueprint п. 16.1, п. 10.2).

func TestMaskPAN(t *testing.T) {
	got, ok := Mask("4111 1111 1111 1111")
	if !ok {
		t.Fatal("PAN не должен исключаться")
	}
	// первые 6 и последние 4 цифры видны, середина скрыта, разделители сохранены
	want := "4111 11** **** 1111"
	if got != want {
		t.Fatalf("PAN: got %q want %q", got, want)
	}
}

func TestMaskPhone(t *testing.T) {
	got, ok := Mask("+7 999 123-45-67")
	if !ok {
		t.Fatal("phone не должен исключаться")
	}
	// код + последние 2 видны
	if got == "+7 999 123-45-67" {
		t.Fatalf("phone не замаскирован: %q", got)
	}
	if len(got) != len("+7 999 123-45-67") {
		t.Fatalf("phone: длина изменилась: %q", got)
	}
}

func TestMaskEmail(t *testing.T) {
	got, ok := Mask("ivan@example.com")
	if !ok {
		t.Fatal("email не должен исключаться")
	}
	want := "i***@example.com"
	if got != want {
		t.Fatalf("email: got %q want %q", got, want)
	}
}

func TestMaskIP(t *testing.T) {
	got, ok := Mask("192.168.0.1")
	if !ok {
		t.Fatal("IP не должен исключаться")
	}
	want := "192.168.0.*"
	if got != want {
		t.Fatalf("IP: got %q want %q", got, want)
	}
}

func TestMaskGovID(t *testing.T) {
	// ИНН 10 цифр: первый и последний видны, длина сохранена
	got, ok := Mask("7707083893")
	if !ok {
		t.Fatal("ИНН не должен исключаться")
	}
	want := "7********3"
	if got != want {
		t.Fatalf("ИНН: got %q want %q", got, want)
	}
}

func TestMaskShortExcluded(t *testing.T) {
	for _, v := range []string{"", "a", "ab", "abc", "abcd", "1234"} {
		if _, ok := Mask(v); ok {
			t.Fatalf("значение %q (<%d) должно исключаться из пула", v, MinLen)
		}
	}
}

func TestMaskFreeTextTruncated(t *testing.T) {
	long := ""
	for len(long) < MaxStringChars+50 {
		long += "свободный текст с длинным содержимым. "
	}
	got, ok := Mask(long)
	if !ok {
		t.Fatal("длинный текст не должен исключаться")
	}
	if len([]rune(got)) > MaxStringChars+1 { // +1 на маркер …
		t.Fatalf("текст не усечён: %d rune", len([]rune(got)))
	}
}

func TestMaskNoRawPII(t *testing.T) {
	// интегральная проверка: маскированные значения не содержат полного ПИИ
	cases := map[string]string{
		"4111111111111111":   "4111111111111", // PAN середина
		"ivan.petrov@ex.com": "ivan.petrov",   // email local
		"7707083893":         "7070838",       // ИНН середина
	}
	for raw, secret := range cases {
		got, _ := Mask(raw)
		if contains(got, secret) && len(secret) > 4 {
			t.Fatalf("маскированное значение %q содержит сырой фрагмент %q", got, secret)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// FuzzMask — устойчивость маскировщика (blueprint п. 16.10).
func FuzzMask(f *testing.F) {
	f.Add("4111 1111 1111 1111")
	f.Add("ivan@example.com")
	f.Add("+7 999 123-45-67")
	f.Add("192.168.0.1")
	f.Add("")
	f.Fuzz(func(t *testing.T, v string) {
		got, _ := Mask(v) // не должно паниковать
		if len(got) > 0 && len(v) < MinLen {
			t.Fatalf("короткое значение %q не исключено", v)
		}
	})
}
