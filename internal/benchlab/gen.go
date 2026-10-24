package benchlab

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// gen — генератор одного позитивного значения конкретного recognizer'я.
type gen struct {
	id  string // RecognizerID из rules.Default()
	new func(rng *rand.Rand) string
}

// gens — покрытие всех recognizer'ов слоя 1 (rules.Default(), этап 3):
// валидные значения с контрольными суммами (ИНН/СНИЛС/Лун/IBAN) и форматные.
var gens = []gen{
	{id: "rules/email", new: genEmail},
	{id: "rules/phone", new: genPhone},
	{id: "rules/inn", new: genINN},
	{id: "rules/snils", new: genSNILS},
	{id: "rules/passport", new: genPassport},
	{id: "rules/luhn", new: genLuhn},
	{id: "rules/bank_account", new: genBankAccount},
	{id: "rules/iban", new: genIBAN},
	{id: "rules/ip", new: genIP},
	{id: "rules/date", new: genDate},
	{id: "rules/uuid", new: genUUID},
}

// negatives — шаблоны значений, гарантированно не матчащихся ни одним
// recognizer'ом (инвариант проверяется тестом TestNegativeInvariant).
var negatives = []func(rng *rand.Rand) string{
	genAlpha,       // буквенная строка
	genRef,         // буквы+цифры с разделителями
	genShortDigits, // 8–9 цифр (ни один recognizer не матчит)
	genLongDigits,  // 21–24 цифры (счёт — 20, Лун — ≤19)
	genBadDate,     // месяц 13 — валидатор дат отсекает
	genNoDomain,    // "user@nodomain" — email без точки в домене
}

func genEmail(rng *rand.Rand) string {
	return fmt.Sprintf("user%d.%d@example%d.org", rng.IntN(100000), rng.IntN(100), rng.IntN(1000))
}

func genPhone(rng *rand.Rand) string {
	d := fmt.Sprintf("9%09d", rng.IntN(1_000_000_000))
	switch rng.IntN(4) {
	case 0:
		return "+7" + d
	case 1:
		return "8 " + d[:3] + " " + d[3:6] + " " + d[6:8] + " " + d[8:]
	case 2:
		return "+7(" + d[:3] + ") " + d[3:6] + "-" + d[6:8] + "-" + d[8:]
	default:
		return d // 10 цифр с ведущей 9
	}
}

var innW10 = [...]int{2, 4, 10, 3, 5, 9, 4, 6, 8}
var innW11 = [...]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
var innW12 = [...]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}

// genINN — ИНН 10/12 цифр с валидной контрольной суммой (спецификация ФНС,
// зеркало inn.go; формула продублирована, чтобы benchlab не лез в internal).
func genINN(rng *rand.Rand) string {
	if rng.IntN(3) == 0 { // 12-значный
		d := make([]int, 10)
		for i := range d {
			d[i] = int(rng.IntN(10))
		}
		c11, c12 := innCtrl2(d)
		return digitsString(d, c11, c12)
	}
	d := make([]int, 9)
	for i := range d {
		d[i] = int(rng.IntN(10))
	}
	sum := 0
	for i, v := range d {
		sum += v * innW10[i]
	}
	return digitsString(d, sum%11%10)
}

func innCtrl2(d []int) (int, int) {
	sum := 0
	for i, v := range d {
		sum += v * innW11[i]
	}
	c11 := sum % 11 % 10
	sum2 := 0
	for i := 0; i < 10; i++ {
		sum2 += d[i] * innW12[i]
	}
	sum2 += c11 * innW12[10]
	return c11, sum2 % 11 % 10
}

func digitsString(d []int, check ...int) string {
	var b strings.Builder
	for _, v := range d {
		b.WriteByte(byte('0' + v))
	}
	for _, c := range check {
		b.WriteByte(byte('0' + c))
	}
	return b.String()
}

// genSNILS — СНИЛС с валидной контрольной суммой (зеркало snils.go).
func genSNILS(rng *rand.Rand) string {
	d := make([]int, 9)
	for {
		for i := range d {
			d[i] = int(rng.IntN(10))
		}
		if !allSame(d) {
			break
		}
	}
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
	s := digitsString(d, check/10, check%10)
	if rng.IntN(2) == 0 {
		return s[:3] + "-" + s[3:6] + "-" + s[6:9] + " " + s[9:]
	}
	return s
}

func allSame(d []int) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}

// genPassport — паспорт РФ: серия 4 цифры + номер 6 цифр (не нулевой),
// не более одного пробела (зеркало passport.go).
func genPassport(rng *rand.Rand) string {
	s := fmt.Sprintf("%04d%06d", rng.IntN(10000), rng.IntN(999999)+1)
	if rng.IntN(2) == 0 {
		return s[:4] + " " + s[4:]
	}
	return s
}

// genLuhn — PAN 16 цифр с валидной контрольной суммой Луна (зеркало luhn.go).
// Контрольная цифра считается как добивка суммы (удвоение — на чётных
// индексах 16-значного PAN, правый край — контрольная цифра).
func genLuhn(rng *rand.Rand) string {
	prefix := []int{4, 5, 2, 3}[rng.IntN(4)]
	d := make([]int, 15)
	d[0] = prefix
	for i := 1; i < 15; i++ {
		d[i] = int(rng.IntN(10))
	}
	sum := 0
	for i, n := range d {
		if i%2 == 0 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	s := digitsString(d, (10-sum%10)%10)
	if rng.IntN(2) == 0 {
		return s[:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:]
	}
	return s
}

// genBankAccount — расчётный счёт РФ: 20 цифр, не нулевой (зеркало
// bank_account.go; без ключевания с БИК — recognizer её не требует).
func genBankAccount(rng *rand.Rand) string {
	return fmt.Sprintf("40802%015d", rng.IntN(1_000_000_000_000_000))
}

// genIBAN — IBAN DE… с валидной контрольной суммой mod-97 (ISO 13616;
// зеркало iban.go). BBAN DE — 18 цифр.
func genIBAN(rng *rand.Rand) string {
	bban := fmt.Sprintf("%018d", rng.IntN(1_000_000_000_000_000_000))
	rem := mod97(bban + "131400") // D=13, E=14, контрольные "00"
	s := fmt.Sprintf("DE%02d%s", 98-rem, bban)
	if rng.IntN(2) == 0 {
		return s[:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:16] + " " + s[16:]
	}
	return s
}

// mod97 — остаток mod 97 строки цифр (букв в аргументе нет).
func mod97(s string) int {
	rem := 0
	for i := 0; i < len(s); i++ {
		rem = (rem*10 + int(s[i]-'0')) % 97
	}
	return rem
}

func genIP(rng *rand.Rand) string {
	if rng.IntN(4) == 0 {
		return fmt.Sprintf("2001:db8::%x", rng.IntN(65536)+1)
	}
	switch rng.IntN(3) {
	case 0:
		return fmt.Sprintf("10.%d.%d.%d", rng.IntN(256), rng.IntN(256), rng.IntN(256))
	case 1:
		return fmt.Sprintf("192.168.%d.%d", rng.IntN(256), rng.IntN(255)+1)
	default:
		return fmt.Sprintf("172.16.%d.%d", rng.IntN(256), rng.IntN(255)+1)
	}
}

func genDate(rng *rand.Rand) string {
	y := 1950 + rng.IntN(76)
	m := 1 + rng.IntN(12)
	d := 1 + rng.IntN(28)
	switch rng.IntN(3) {
	case 0:
		return fmt.Sprintf("%02d.%02d.%04d", d, m, y)
	case 1:
		return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
	default:
		return fmt.Sprintf("%02d/%02d/%04d", d, m, y)
	}
}

var hexDigits = "0123456789abcdef"

func genUUID(rng *rand.Rand) string {
	var b strings.Builder
	b.Grow(36)
	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			b.WriteByte('-')
		default:
			b.WriteByte(hexDigits[rng.IntN(16)])
		}
	}
	s := b.String()
	if rng.IntN(4) == 0 {
		return "{" + s + "}"
	}
	return s
}

func genAlpha(rng *rand.Rand) string {
	n := 5 + rng.IntN(26)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte('a' + byte(rng.IntN(26)))
	}
	return b.String()
}

func genRef(rng *rand.Rand) string {
	return fmt.Sprintf("%s-%04d-%s", alpha(3, rng), rng.IntN(10000), alpha(2, rng))
}

func alpha(n int, rng *rand.Rand) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte('A' + byte(rng.IntN(26)))
	}
	return b.String()
}

func genShortDigits(rng *rand.Rand) string {
	if rng.IntN(2) == 0 {
		return fmt.Sprintf("%08d", rng.IntN(100_000_000))
	}
	return fmt.Sprintf("%09d", rng.IntN(1_000_000_000))
}

func genLongDigits(rng *rand.Rand) string {
	n := 21 + rng.IntN(4)
	var b strings.Builder
	b.WriteByte(byte('1' + rng.IntN(9)))
	for i := 1; i < n; i++ {
		b.WriteByte(byte('0' + rng.IntN(10)))
	}
	return b.String()
}

func genBadDate(rng *rand.Rand) string {
	return fmt.Sprintf("%02d.13.%04d", 1+rng.IntN(28), 2101+rng.IntN(900))
}

func genNoDomain(rng *rand.Rand) string {
	return fmt.Sprintf("user%d@nodomain", rng.IntN(10000))
}
