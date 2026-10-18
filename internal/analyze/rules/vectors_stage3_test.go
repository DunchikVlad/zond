package rules

import (
	"strconv"
	"testing"
)

// Золотые вектора новых recognizer'ов этапа 3 (blueprint п. 16.1).
// Checksum-типы (СНИЛС, IBAN, счёт по БИК) — генераторы по спецификации.

// seq9 возвращает 9-значную строку из числа (с ведущими нулями).
func seq9(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 9 {
		s = "0" + s
	}
	return s
}

// seq10 возвращает 10-значную строку из числа (с ведущими нулями).
func seq10(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}

// corruptDigit портит i-й разряд (заменяет на (d+1)%10) — гарантированно ломает
// контрольную сумму для линейных checksum-схем.
func corruptDigit(s string, i int) string {
	b := []byte(s)
	b[i] = byte('0' + (int(b[i]-'0')+1)%10)
	return string(b)
}

// TestInnVectorsBulk — ≥50 валидных + ≥50 невалидных ИНН (п. 16.1).
// Валидные — сгенерированы по ФНС; невалидные — испорченный контрольный разряд.
func TestInnVectorsBulk(t *testing.T) {
	var valid []string
	for i := 0; i < 30; i++ {
		valid = append(valid, makeINN10(seq9(700000000+i*7+1)))
	}
	for i := 0; i < 25; i++ {
		valid = append(valid, makeINN12(seq10(7000000000+i*7+1)))
	}
	var invalid []string
	for i := 0; i < 55; i++ {
		base := makeINN10(seq9(500000000 + i*11 + 3))
		invalid = append(invalid, corruptDigit(base, 9)) // ломаем контрольный разряд
	}
	runVectors(t, innRecognizer{}, valid, invalid)
}

// TestLuhnVectorsBulk — ≥50 валидных + ≥50 невалидных PAN (п. 16.1).
func TestLuhnVectorsBulk(t *testing.T) {
	var valid []string
	for i := 0; i < 55; i++ {
		valid = append(valid, makeLuhn(seq10(4000000000+i*13+5)+"12")) // 12 цифр base + check
	}
	var invalid []string
	for i := 0; i < 55; i++ {
		base := makeLuhn(seq10(5000000000+i*17+1) + "34")
		invalid = append(invalid, corruptDigit(base, len(base)-1))
	}
	runVectors(t, luhnRecognizer{}, valid, invalid)
}

// TestSnilsVectorsBulk — ≥50 валидных + ≥50 невалидных СНИЛС (п. 16.1).
func TestSnilsVectorsBulk(t *testing.T) {
	var valid []string
	for i := 0; i < 55; i++ {
		s9 := seq9(100000000 + i*37 + 7)
		if s9[0] == '0' { // избегаем «все одинаковые/нулевой» частный случай
			s9 = "1" + s9[1:]
		}
		valid = append(valid, makeSNILS(s9))
	}
	var invalid []string
	for i := 0; i < 55; i++ {
		s9 := seq9(200000000 + i*41 + 1)
		base := makeSNILS(s9)
		invalid = append(invalid, corruptDigit(base, 10))
	}
	runVectors(t, snilsRecognizer{}, valid, invalid)
}

// --- СНИЛС ---

func makeSNILS(first9 string) string {
	d := digitsOf(first9) // 9 цифр
	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * (9 - i)
	}
	var check int
	switch {
	case sum < 100:
		check = sum
	case sum == 100 || sum == 101:
		check = 0
	default:
		check = sum % 101
		if check == 100 {
			check = 0
		}
	}
	return first9 + strconv.Itoa(check/10) + strconv.Itoa(check%10)
}

func TestSnilsVectors(t *testing.T) {
	valid := []string{
		makeSNILS("112233445"),
		makeSNILS("123456789"),
		makeSNILS("987654321"),
		makeSNILS("205876513"),
		// с разделителями "XXX-XXX-XXX YY"
		formatSNILS(makeSNILS("112233445")),
		formatSNILS(makeSNILS("405918273")),
	}
	invalid := []string{
		"",
		"11223344590",  // неверная контрольная сумма
		"1122334450",   // 10 цифр
		"112233445999", // 12 цифр
		"112-233-44A",  // буква
		"00000000000",  // нулевой
		"11111111111",  // одинаковые цифры
	}
	// испорченный последний разряд валидного СНИЛС
	bad := []byte(makeSNILS("112233445"))
	bad[10] = byte('0' + (int(bad[10]-'0')+1)%10)
	invalid = append(invalid, string(bad))
	runVectors(t, snilsRecognizer{}, valid, invalid)
}

func formatSNILS(s string) string { // "12345678901" → "123-456-789 01"
	return s[0:3] + "-" + s[3:6] + "-" + s[6:9] + " " + s[9:11]
}

// --- Паспорт РФ ---

func TestPassportVectors(t *testing.T) {
	runVectors(t, passportRecognizer{}, []string{
		"4509123456",
		"4509 123456",
		"0315123456",
		"0509 123456", // серия с ведущим 0 допустима
		"7710 987654",
	}, []string{
		"",
		"4509 000000",  // нулевой номер
		"450912345",    // 9 цифр
		"45091234567",  // 11 цифр
		"4509 12 3456", // пробелы внутри
		"45A9 123456",  // буква
		"4509-123456",  // дефис не допускается
	})
}

// --- Расчётный счёт РФ ---

func TestBankAccountVectors(t *testing.T) {
	runVectors(t, bankAccountRecognizer{}, []string{
		"40702810038000012345",
		"40802840500001000001",
		"30101810400000000225",
		"40702 810 0 3800 0012345", // с пробелами
	}, []string{
		"",
		"00702810038000012345",  // ведущий 0
		"00000000000000000000",  // нулевой
		"4070281003800001234",   // 19 цифр
		"407028100380000123456", // 21 цифра
		"40702810A8000012345",   // буква
	})
}

func TestBankAccountKeyCheck(t *testing.T) {
	// согласованность генерации и проверки ключа (положение ЦБ):
	// БИК 044525225 (3 последние — 225); счёт 20 цифр: 8 + ключ(9-й) + 11.
	bik := "044525225"
	found := false
	for k := 0; k < 10; k++ {
		acc := "40702810" + strconv.Itoa(k) + "00000000011" // 8+1+11 = 20
		if len(acc) != 20 {
			t.Fatalf("база счёта не 20 цифр: %q", acc)
		}
		if BankAccountKeyCheck(bik, acc) {
			found = true
			if !(bankAccountRecognizer{}).Match(acc) {
				t.Fatalf("валидный по ключу счёт отклонён форматом: %q", acc)
			}
		}
	}
	if !found {
		t.Fatal("не удалось подобрать контрольный разряд для БИК")
	}
}

// --- IBAN ---

func TestIbanVectors(t *testing.T) {
	runVectors(t, ibanRecognizer{}, []string{
		"GB29NWBK60161331926819", // эталон ISO
		"DE89370400440532013000",
		"FR1420041010050500013M02606",
		"NL91ABNA0417164300",
		"GB29 NWBK 6016 1331 9268 19", // с пробелами
	}, []string{
		"",
		"GB29NWBK60161331926818",     // неверная контрольная сумма
		"gb29NWBK60161331926819",     // строчные буквы страны
		"GB29NWBK601613319268",       // короткий
		"GB29 NWBK 6016 1331 9268 1", // 17 < 18 (GB=22)
		"12AANWBK60161331926819",     // цифры в коде страны
		"GB29NWBK6016133192681!",     // спецсимвол
	})
}

// --- IP ---

func TestIPVectors(t *testing.T) {
	runVectors(t, ipRecognizer{}, []string{
		"192.168.0.1",
		"10.0.0.1",
		"255.255.255.255",
		"8.8.8.8",
		"::1",
		"2001:db8::1",
		"fe80::1",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
	}, []string{
		"",
		"256.1.1.1",        // октет >255
		"192.168.0",        // 3 октета
		"192.168.0.1.5",    // 5 октетов
		"192.168.0.1/24",   // CIDR
		"192.168.0.1:8080", // host:port
		"fe80::1%eth0",     // зона
		"::g",              // не hex
		"300.300.300.300",
		"abc.def.ghi.jkl",
	})
}

// --- Дата ---

func TestDateVectors(t *testing.T) {
	runVectors(t, dateRecognizer{}, []string{
		"31.12.1990",
		"01.01.2000",
		"29.02.2000", // високосный
		"28.02.2021",
		"15/07/1985",
		"2000-02-29", // ISO високосный
		"2021-12-31", // ISO
		"05-03-1999", // DD-MM-YYYY
		"1.1.2000",   // однозначные день/месяц без ведущего нуля
	}, []string{
		"",
		"32.01.2000", // день >31
		"31.04.2000", // 31 апреля
		"29.02.2021", // не високосный
		"00.01.2000", // день 0
		"01.13.2000", // месяц 13
		"01.00.2000", // месяц 0
		"2000-13-01", // ISO месяц 13
		"31.12.1899", // год <1900
		"01.01.2200", // год >2100
		"2000/01/01", // смешанные разделители
		"ab.cd.efgh",
	})
}

// --- UUID ---

func TestUUIDVectors(t *testing.T) {
	runVectors(t, uuidRecognizer{}, []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"550E8400-E29B-41D4-A716-446655440000", // upper hex
		"{550e8400-e29b-41d4-a716-446655440000}",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	}, []string{
		"",
		"550e8400e29b41d4a716446655440000",      // без дефисов
		"550e8400-e29b-41d4-a716-44665544000",   // короткий
		"550e8400-e29b-41d4-a716-4466554400000", // длинный
		"550e8400-e29b-41d4-a716-44665544000g",  // не hex
		"550e8400-e29b_41d4_a716_446655440000",  // неверный разделитель
	})
}

// --- Регистрация полного набора этапа 3 ---

func TestDefaultStage3Complete(t *testing.T) {
	got := map[string]bool{}
	for _, r := range Default() {
		got[r.ID()] = true
	}
	want := []string{
		"rules/email", "rules/phone", "rules/inn", "rules/snils",
		"rules/passport", "rules/luhn", "rules/bank_account", "rules/iban",
		"rules/ip", "rules/date", "rules/uuid",
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("в Default() отсутствует %s", id)
		}
	}
	if len(Default()) != len(want) {
		t.Errorf("Default() = %d recognizer'ов, ожидалось %d", len(Default()), len(want))
	}
}

// TestChecksumRecognizers — типы с самодостаточной контрольной суммой (п. 5.6:
// checksum → 0.99).
func TestChecksumRecognizers(t *testing.T) {
	checksum := map[string]bool{}
	for _, r := range Default() {
		checksum[r.ID()] = r.HasChecksum()
	}
	for _, id := range []string{"rules/inn", "rules/snils", "rules/luhn", "rules/iban"} {
		if !checksum[id] {
			t.Errorf("%s должен иметь контрольную сумму (HasChecksum)", id)
		}
	}
	// bank_account без БИК — форматный (HasChecksum=false): ключ требует БИК
	if checksum["rules/bank_account"] {
		t.Error("rules/bank_account без БИК не должен быть checksum (нужен БИК)")
	}
}
