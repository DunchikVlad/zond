package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// Золотые вектора (blueprint п. 16.1). Этап 1: стартовые наборы;
// ≥50 валидных/невалидных на тип и порт полного набора — этап 3 (R7).

func runVectors(t *testing.T, r Recognizer, valid, invalid []string) {
	t.Helper()
	for _, v := range valid {
		if !r.Match(v) {
			t.Errorf("%s: валидное значение отклонено: %q", r.ID(), v)
		}
	}
	for _, v := range invalid {
		if r.Match(v) {
			t.Errorf("%s: невалидное значение принято: %q", r.ID(), v)
		}
	}
}

func TestEmailVectors(t *testing.T) {
	runVectors(t, emailRecognizer{}, []string{
		"a@b.co",
		"user@example.com",
		"user.name+tag@example.com",
		"x_y-z@sub.domain.org",
		"user123@test-domain.ru",
		"u@x.io",
		"first.last@corp.example.travel",
		"o'neil@example.com", // апостроф допустим в local-part
	}, []string{
		"",
		"a@b",
		"a@",
		"@b.com",
		"a b@c.com",
		"a@b..com",
		"a@.com",
		"a@b.c",
		`a"b@c.com`,
		"a@b_com.com",
		"a@b.-com",
		"plainaddress",
		"a@почта.ru", // пока только ASCII-домены (cyr-домены — этап 3, punycode)
	})
}

func TestPhoneVectors(t *testing.T) {
	runVectors(t, phoneRecognizer{}, []string{
		"+7 999 123-45-67",
		"89991234567",
		"8 999 123 45 67",
		"+7 (495) 123-45-67",
		"+7-999-123-45-67",
		"9991234567",
		"+7(999)1234567",
		"8(999)123-45-67",
	}, []string{
		"",
		"12345",
		"abc",
		"+1 999 123 45 67",  // 11 цифр не на 7/8
		"999 123 45",        // 9 цифр
		"+7 999 123 45 6",   // 10 цифр не на 9
		"+7 999 123 45 678", // 12 цифр
		"++7 999 123 45 67", // два плюса
		"+7 999 123 45 6a",
		"7(999)123-45-6",
	})
}

// makeINN10/12 формируют ИНН с корректной контрольной суммой (спецификация ФНС).
func makeINN10(first9 string) string {
	d := digitsOf(first9)
	check := weightedCheck(d, innW10[:])
	return first9 + strconv.Itoa(check)
}

// makeINN12 формирует 12-значный ИНН с корректными 11-й и 12-й контрольными цифрами.
func makeINN12(first10 string) string {
	d := digitsOf(first10) // 10 цифр
	c11 := weightedCheck(d, innW11[:])
	n11 := append(append([]int(nil), d...), c11)
	c12 := weightedCheck(n11, innW12[:])
	return first10 + strconv.Itoa(c11) + strconv.Itoa(c12)
}

func digitsOf(s string) []int {
	d := make([]int, len(s))
	for i := range s {
		d[i] = int(s[i] - '0')
	}
	return d
}

func weightedCheck(d, w []int) int {
	sum := 0
	for i := range d {
		sum += d[i] * w[i]
	}
	return sum % 11 % 10
}

func TestInnVectors(t *testing.T) {
	valid10 := []string{
		makeINN10("770708389"),
		makeINN10("770123456"),
		makeINN10("500100732"),
		makeINN10("631100801"),
		makeINN10("772816897"),
		makeINN10("366000111"),
		makeINN10("525000222"),
		makeINN10("616000333"),
		makeINN10("701000444"),
		makeINN10("420000555"),
	}
	valid12 := []string{
		makeINN12("7701234567"),
		makeINN12("5001007321"),
		makeINN12("6311008012"),
		makeINN12("7728168973"),
		makeINN12("3660001114"),
		makeINN12("5250002225"),
		makeINN12("6160003336"),
		makeINN12("7010004447"),
		makeINN12("4200005558"),
		makeINN12("7707083899"),
	}
	invalid := []string{
		"",
		"7707083890",     // 10 цифр, неверная сумма
		"770123456712",   // 12 цифр, неверная сумма
		"77070838901",    // 11 цифр
		"77070838912345", // 14 цифр
		"7707A83893",     // буква
		"7707 838 903",   // пробелы
	}
	// контроль негатива: испорченный последний разряд валидного ИНН
	bad := []byte(makeINN10("770708389"))
	bad[9] = byte('0' + (int(bad[9]-'0')+1)%10)
	invalid = append(invalid, string(bad))
	runVectors(t, innRecognizer{}, append(valid10, valid12...), invalid)
}

// makeLuhn формирует номер с корректной контрольной суммой Луна.
func makeLuhn(base string) string {
	d := make([]byte, len(base))
	copy(d, base)
	d = append(d, '0')
	if !luhnOK(d) { // подберём check digit
		for c := '1'; c <= '9'; c++ {
			d[len(d)-1] = byte(c)
			if luhnOK(d) {
				break
			}
		}
	}
	return string(d)
}

func TestLuhnVectors(t *testing.T) {
	runVectors(t, luhnRecognizer{}, []string{
		"4111111111111111",
		"4242424242424242",
		"5555555555554444",
		"378282246310005",
		"6011111111111117",
		makeLuhn("22001234567894"),
		makeLuhn("4000000000000"),
		makeLuhn("1234567890123"),
		makeLuhn("9876501234567"),
	}, []string{
		"",
		"4111111111111112", // неверный check digit
		"4242424242424241",
		"4111-1111-1111-1112",
		"411111111111",         // 12 цифр
		"41111111111111111111", // 20 цифр
		"4111ABCD11111111",
		"4111 1111 1111 111a",
		"4",
		"----",
	})
}

func TestConfidenceMapping(t *testing.T) {
	cases := []struct {
		name string
		m    Match
		want float64
	}{
		{"checksum", Match{HasChecksum: true, Matched: 1, Total: 100}, 0.99},
		{"strong", Match{Matched: 9, Total: 10}, 0.90},
		{"mid", Match{Matched: 6, Total: 10}, 0.70},
		{"weak", Match{Matched: 2, Total: 10}, 0.50},
		{"empty", Match{Matched: 0, Total: 0}, 0},
	}
	for _, c := range cases {
		if got := Confidence(c.m); got != c.want {
			t.Errorf("%s: Confidence = %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

func TestAnalyzeOmitsEmptyMatches(t *testing.T) {
	ms := Analyze([]string{"a@b.co", "not-an-email"}, emailRecognizer{})
	if len(ms) != 1 || ms[0].Matched != 1 || ms[0].Total != 2 {
		t.Fatalf("неожиданный результат Analyze: %+v", ms)
	}
	if ms[0].Label != verdict.Label("EMAIL") {
		t.Fatalf("лейбл: %v", ms[0].Label)
	}
}

func TestLabels(t *testing.T) {
	var (
		email = emailRecognizer{}
		phone = phoneRecognizer{}
		inn   = innRecognizer{}
		luhn  = luhnRecognizer{}
	)
	if email.Label() != verdict.Label("EMAIL") ||
		phone.Label() != verdict.Label("PHONE") ||
		inn.Label() != verdict.Label("TAX_ID") ||
		luhn.Label() != verdict.Label("CARD_NUMBER") {
		t.Fatal("лейблы recognizer'ов не совпадают с таксономией")
	}
}

func TestInnHelpersAgreeWithRecognizer(t *testing.T) {
	// согласованность генераторов тестовых данных с кодом recognizer'а
	var inn = innRecognizer{}
	if !inn.Match(makeINN10("770708389")) {
		t.Fatal("makeINN10 сгенерировал невалидный ИНН")
	}
	if !inn.Match(makeINN12("7701234567")) {
		t.Fatal("makeINN12 сгенерировал невалидный ИНН")
	}
	if strings.ContainsAny(makeINN10("770708389"), " \t") {
		t.Fatal("makeINN10 вернул мусор")
	}
}
