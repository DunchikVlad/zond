package evalset

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// Генераторы значений датасета (blueprint п. 16.6): позитивы по лейблам
// таксономии и негативы (спуфы, free_text с встроенным PII, mixed-типы,
// полиморфные документы). Все значения однострочные; форматы варьируются
// через rng — детерминированно при фиксированном seed.

// generator — состояние генерации: общий rng, число значений на колонку
// и счётчик идентификаторов (ровно 1 числовой id на 20 вызовов — доля
// UUID-детекта в каждой колонке стабильно 0.95 при Rows=20).
type generator struct {
	rng    *rand.Rand
	rows   int
	identN int
}

// positiveValues — Rows значений позитивной колонки ожидаемого лейбла.
func (g *generator) positiveValues(label verdict.Label) []string {
	out := make([]string, 0, g.rows)
	for i := 0; i < g.rows; i++ {
		out = append(out, g.positiveValue(label))
	}
	return out
}

// positiveValue — одно значение позитивной колонки.
func (g *generator) positiveValue(label verdict.Label) string {
	switch label {
	case "PHONE":
		return g.genPhone()
	case "EMAIL":
		return g.genEmail()
	case "TAX_ID":
		if g.rng.IntN(2) == 0 {
			return makeINN10(g.rng)
		}
		return makeINN12(g.rng)
	case "SNILS":
		return g.genSNILS()
	case "CARD_NUMBER":
		return g.genCard()
	case "BANK_ACCOUNT":
		return g.genBankAccount()
	case "PASSPORT_ID":
		return g.genPassport()
	case "IP_ADDRESS":
		return g.genIP()
	case "DATE_OF_BIRTH":
		return g.genDate(1940, 2010)
	case "DATE_TIME":
		return g.genDate(2015, 2026)
	case "IDENTIFIER":
		return g.genIdentifier()
	case "PERSON_NAME":
		return g.genPersonName()
	case "ADDRESS":
		return g.genAddress()
	case "GEO_LOCATION":
		return g.genGeo()
	case "FREE_TEXT":
		return g.genCleanText()
	case "NUMERIC_MEASURE":
		return g.genNumeric()
	case "BOOLEAN":
		return g.genBool()
	case "JSON_DOC":
		return g.genJSON()
	default: // UNKNOWN и будущие лейблы без recognizer'а
		return g.genUnknown()
	}
}

// randDigits — строка из n случайных цифр.
func (g *generator) randDigits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + g.rng.IntN(10)))
	}
	return b.String()
}

// genPhone — RU-мобильный номер в одном из 5 форматов recognizer'а.
func (g *generator) genPhone() string {
	d := "9" + g.randDigits(9) // 10 цифр с ведущей 9
	switch g.rng.IntN(5) {
	case 0:
		return "+7 " + d[0:3] + " " + d[3:6] + "-" + d[6:8] + "-" + d[8:10]
	case 1:
		return "8(" + d[0:3] + ")" + d[3:6] + "-" + d[6:8] + "-" + d[8:10]
	case 2:
		return "+7" + d
	case 3:
		return "8" + d
	default:
		return d
	}
}

// genEmail — адрес из словаря слов и доменов.
func (g *generator) genEmail() string {
	local := emailWords[g.rng.IntN(len(emailWords))]
	switch g.rng.IntN(4) {
	case 0:
		local += "." + emailWords[g.rng.IntN(len(emailWords))]
	case 1:
		local += strconv.Itoa(1 + g.rng.IntN(99))
	case 2:
		local += "_" + firstNamesEN[g.rng.IntN(len(firstNamesEN))%len(emailWords)]
	}
	return local + "@" + emailDomains[g.rng.IntN(len(emailDomains))]
}

// genSNILS — валидный СНИЛС, сплошной или с разделителями.
func (g *generator) genSNILS() string {
	s := makeSNILS(g.rng)
	if g.rng.IntN(2) == 0 {
		return s
	}
	return s[0:3] + "-" + s[3:6] + "-" + s[6:9] + " " + s[9:11]
}

// genCard — Luhn-валидный PAN 16 цифр (Visa / MasterCard / Мир),
// сплошной или группами по 4.
func (g *generator) genCard() string {
	var prefix string
	switch g.rng.IntN(3) {
	case 0: // Visa
		prefix = "4"
	case 1: // MasterCard 51–55
		prefix = "5" + strconv.Itoa(1+g.rng.IntN(5))
	default: // Мир 2200–2204
		prefix = "220" + strconv.Itoa(g.rng.IntN(5))
	}
	s := makeLuhnDigits(g.rng, prefix+g.randDigits(15-len(prefix)))
	if g.rng.IntN(2) == 0 {
		return s
	}
	return group4(s)
}

// ibanCountries — страны для IBAN и длины BBAN (итоговая длина 18–27).
var ibanCountries = []struct {
	code        string
	bbanLen     int
	withLetters bool
}{
	{"DE", 18, false}, // 22
	{"NL", 14, true},  // 18
	{"GB", 18, true},  // 22
	{"FR", 23, true},  // 27
	{"RU", 17, false}, // 21
}

// genIBAN — валидный IBAN (мод-97), сплошной или группами по 4.
func (g *generator) genIBAN() string {
	c := ibanCountries[g.rng.IntN(len(ibanCountries))]
	var bban string
	for len(bban) < c.bbanLen {
		if c.withLetters && g.rng.IntN(3) == 0 {
			bban += string(rune('A' + g.rng.IntN(26)))
		} else {
			bban += strconv.Itoa(g.rng.IntN(10))
		}
	}
	s := makeIBAN(c.code, bban)
	if g.rng.IntN(2) == 0 {
		return s
	}
	return group4(s)
}

// genBankAccount — 20-значный счёт (40802/40702 + 15 цифр) в 2/3 случаев,
// валидный IBAN — в 1/3.
func (g *generator) genBankAccount() string {
	if g.rng.IntN(3) == 0 {
		return g.genIBAN()
	}
	var prefix string
	if g.rng.IntN(2) == 0 {
		prefix = "40802"
	} else {
		prefix = "40702"
	}
	s := prefix + g.randDigits(15)
	if g.rng.IntN(2) == 0 {
		return s
	}
	return group4(s)
}

// genPassport — паспорт РФ: серия 4 цифры + номер 000001–999999.
func (g *generator) genPassport() string {
	series := g.randDigits(4)
	num := fmt.Sprintf("%06d", 1+g.rng.IntN(999999))
	if g.rng.IntN(2) == 0 {
		return series + " " + num
	}
	return series + num
}

// genIP — IPv4 (2/3) без ведущих нулей или IPv6 из 16 случайных байт (1/3).
func (g *generator) genIP() string {
	if g.rng.IntN(3) == 0 {
		var b [16]byte
		for i := range b {
			b[i] = byte(g.rng.IntN(256))
		}
		return netip.AddrFrom16(b).String()
	}
	q := make([]string, 4)
	for i := range q {
		q[i] = strconv.Itoa(g.rng.IntN(256))
	}
	return strings.Join(q, ".")
}

// daysInMonth — число дней в месяце (для календарно валидных дат).
func daysInMonth(y, m int) int {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
			return 29
		}
		return 28
	}
	return 0
}

// genDate — календарно валидная дата в одном из 4 форматов recognizer'а:
// DD.MM.YYYY, DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY (без времени).
func (g *generator) genDate(yMin, yMax int) string {
	y := yMin + g.rng.IntN(yMax-yMin+1)
	m := 1 + g.rng.IntN(12)
	d := 1 + g.rng.IntN(daysInMonth(y, m))
	switch g.rng.IntN(4) {
	case 0:
		return fmt.Sprintf("%02d.%02d.%04d", d, m, y)
	case 1:
		return fmt.Sprintf("%02d/%02d/%04d", d, m, y)
	case 2:
		return fmt.Sprintf("%04d-%02d-%02d", y, m, d)
	default:
		return fmt.Sprintf("%02d-%02d-%04d", d, m, y)
	}
}

// genIdentifier — UUIDv4 canonical lowercase (алгоритм должен детектиться
// uuid-recognizer'ом); ровно 1 из 20 вызовов — короткий числовой id.
func (g *generator) genIdentifier() string {
	g.identN++
	if g.identN%20 != 0 {
		var b [16]byte
		for i := range b {
			b[i] = byte(g.rng.IntN(256))
		}
		b[6] = (b[6] & 0x0f) | 0x40 // version 4
		b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx
		h := make([]byte, 32)
		hex.Encode(h, b[:])
		return string(h[0:8]) + "-" + string(h[8:12]) + "-" + string(h[12:16]) + "-" + string(h[16:20]) + "-" + string(h[20:32])
	}
	return strconv.Itoa(1 + g.rng.IntN(999_999_999))
}

// firstRune — первая руна строки (для инициалов).
func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return ""
}

// genPersonName — RU «Фамилия Имя Отчество» / «Фамилия И. О.» или EN «First Last».
func (g *generator) genPersonName() string {
	switch g.rng.IntN(3) {
	case 0:
		return surnamesRU[g.rng.IntN(len(surnamesRU))] + " " +
			firstNamesRU[g.rng.IntN(len(firstNamesRU))] + " " +
			patronymicsRU[g.rng.IntN(len(patronymicsRU))]
	case 1:
		name := firstNamesRU[g.rng.IntN(len(firstNamesRU))]
		patr := patronymicsRU[g.rng.IntN(len(patronymicsRU))]
		return surnamesRU[g.rng.IntN(len(surnamesRU))] + " " + firstRune(name) + ". " + firstRune(patr) + "."
	default:
		return firstNamesEN[g.rng.IntN(len(firstNamesEN))] + " " +
			lastNamesEN[g.rng.IntN(len(lastNamesEN))]
	}
}

// genAddress — почтовый адрес RU: город + улица + дом (+ квартира).
func (g *generator) genAddress() string {
	city := citiesRU[g.rng.IntN(len(citiesRU))]
	street := streetsRU[g.rng.IntN(len(streetsRU))]
	house := 1 + g.rng.IntN(200)
	switch g.rng.IntN(4) {
	case 0:
		return fmt.Sprintf("г. %s, ул. %s, д. %d, кв. %d", city, street, house, 1+g.rng.IntN(500))
	case 1:
		return fmt.Sprintf("г. %s, пр-кт %s, д. %d, кв. %d", city, street, house, 1+g.rng.IntN(500))
	case 2:
		return fmt.Sprintf("г. %s, пер. %s, д. %d", city, street, house)
	default:
		return fmt.Sprintf("г. %s, ул. %s, д. %d", city, street, house)
	}
}

// genGeo — координаты «lat, lon» по 4 знака (шаблон «55.7558, 37.6173»).
func (g *generator) genGeo() string {
	lat := 41.0 + g.rng.Float64()*36.0  // 41–77
	lon := 19.0 + g.rng.Float64()*161.0 // 19–180
	return fmt.Sprintf("%.4f, %.4f", lat, lon)
}

// genCleanText — 1 предложение без структурированного PII (FREE_TEXT-позитивы).
func (g *generator) genCleanText() string {
	if g.rng.IntN(2) == 0 {
		return freeTextCleanRU[g.rng.IntN(len(freeTextCleanRU))]
	}
	return freeTextCleanEN[g.rng.IntN(len(freeTextCleanEN))]
}

// genNumeric — целое 0–100000 или float с 1–2 знаками (чистое число строкой).
func (g *generator) genNumeric() string {
	if g.rng.IntN(2) == 0 {
		return strconv.Itoa(g.rng.IntN(100001))
	}
	if g.rng.IntN(2) == 0 {
		return fmt.Sprintf("%d.%d", g.rng.IntN(10001), g.rng.IntN(10))
	}
	return fmt.Sprintf("%d.%02d", g.rng.IntN(1001), g.rng.IntN(100))
}

// genBool — булево в одном из распространённых строковых видов.
func (g *generator) genBool() string {
	switch g.rng.IntN(6) {
	case 0, 1:
		return "true"
	case 2, 3:
		return "false"
	case 4:
		if g.rng.IntN(2) == 0 {
			return "1"
		}
		return "0"
	default:
		if g.rng.IntN(2) == 0 {
			return "да"
		}
		return "нет"
	}
}

// genJSON — компактный однострочный JSON: объекты 1–2 уровня, массивы.
func (g *generator) genJSON() string {
	w := func() string { return jsonWords[g.rng.IntN(len(jsonWords))] }
	n := func() string { return strconv.Itoa(g.rng.IntN(1000)) }
	switch g.rng.IntN(5) {
	case 0:
		return fmt.Sprintf(`{"%s":%s,"%s":"%s"}`, w(), n(), w(), w())
	case 1:
		return fmt.Sprintf(`{"user":{"id":%s,"name":"%s"},"tags":["%s","%s"]}`, n(), w(), w(), w())
	case 2:
		return fmt.Sprintf(`{"items":[%s,%s,%s],"count":%s}`, n(), n(), n(), n())
	case 3:
		return fmt.Sprintf(`["%s","%s","%s"]`, w(), w(), w())
	default:
		return fmt.Sprintf(`{"%s":{"%s":%s},"flag":true}`, w(), w(), n())
	}
}

// genUnknown — короткий алфавитно-цифровой код без доминирующего типа
// (цифровые раны ≤6 — не пересекаются с recognizer'ами).
func (g *generator) genUnknown() string {
	switch g.rng.IntN(3) {
	case 0:
		n := 4 + g.rng.IntN(3) // 4–6 символов
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte(byte('A' + g.rng.IntN(26)))
		}
		return b.String()
	case 1:
		return fmt.Sprintf("%s%d%s", string(rune('A'+g.rng.IntN(26))), g.rng.IntN(10000), string(rune('A'+g.rng.IntN(26))))
	default:
		return fmt.Sprintf("%s-%d-%s", string(rune('A'+g.rng.IntN(26))), g.rng.IntN(1000), string(rune('A'+g.rng.IntN(26))))
	}
}

// ---------------------------------------------------------------------------
// Негативы
// ---------------------------------------------------------------------------

// spoofValues — спуфы: структура верная, контрольная сумма гарантированно
// неверная (ложняк для слоя 1). target — имитируемый лейбл.
func (g *generator) spoofValues(target verdict.Label) []string {
	out := make([]string, 0, g.rows)
	for i := 0; i < g.rows; i++ {
		out = append(out, g.spoofValue(target))
	}
	return out
}

func (g *generator) spoofValue(target verdict.Label) string {
	switch target {
	case "TAX_ID":
		// валидный ИНН (10 или 12) с испорченной контрольной цифрой
		if g.rng.IntN(2) == 0 {
			return corruptCheck(makeINN10(g.rng))
		}
		return corruptCheck(makeINN12(g.rng))
	case "SNILS":
		return corruptCheck(makeSNILS(g.rng))
	case "CARD_NUMBER":
		s := corruptCheck(g.genCardPlain())
		if g.rng.IntN(2) == 0 {
			return s
		}
		return group4(s)
	case "BANK_ACCOUNT":
		// валидный IBAN с испорченными контрольными цифрами
		s := corruptIBAN(g.genIBAN())
		return s
	default:
		return g.genUnknown()
	}
}

// genCardPlain — Luhn-валидный PAN без группировки (база для спуфов).
func (g *generator) genCardPlain() string {
	var prefix string
	switch g.rng.IntN(3) {
	case 0:
		prefix = "4"
	case 1:
		prefix = "5" + strconv.Itoa(1+g.rng.IntN(5))
	default:
		prefix = "220" + strconv.Itoa(g.rng.IntN(5))
	}
	return makeLuhnDigits(g.rng, prefix+g.randDigits(15-len(prefix)))
}

// corruptIBAN портит контрольные цифры IBAN (разряды 2–3) — mod-97 ≠ 1.
func corruptIBAN(iban string) string {
	check, err := strconv.Atoi(iban[2:4])
	if err != nil {
		return iban
	}
	check = (check + 1 + len(iban)) % 98 // гарантированно иное значение 0–97
	return iban[:2] + fmt.Sprintf("%02d", check) + iban[4:]
}

// freeTextValues — FREE_TEXT со встроенным валидным PII типа emb:
// каждое значение — одно предложение, PII вшит ровно один. В 1/4 случаев
// предложение чистое (без PII) — как в реальных колонках комментариев.
func (g *generator) freeTextValues(emb verdict.Label) []string {
	out := make([]string, 0, g.rows)
	for i := 0; i < g.rows; i++ {
		if g.rng.IntN(4) == 0 {
			out = append(out, g.genCleanText())
			continue
		}
		var tpl string
		if g.rng.IntN(2) == 0 {
			tpl = freeTextTemplatesRU[g.rng.IntN(len(freeTextTemplatesRU))]
		} else {
			tpl = freeTextTemplatesEN[g.rng.IntN(len(freeTextTemplatesEN))]
		}
		out = append(out, fmt.Sprintf(tpl, g.embeddedPII(emb)))
	}
	return out
}

// embeddedPII — валидное значение встраиваемого PII (чексуммы настоящие —
// ловушка для слоя 1: колонка FREE_TEXT, но значения содержат детекты).
func (g *generator) embeddedPII(emb verdict.Label) string {
	switch emb {
	case "PHONE":
		return g.genPhone()
	case "EMAIL":
		return g.genEmail()
	case "TAX_ID":
		if g.rng.IntN(2) == 0 {
			return makeINN10(g.rng)
		}
		return makeINN12(g.rng)
	case "SNILS":
		return makeSNILS(g.rng)
	case "CARD_NUMBER":
		return g.genCard()
	default:
		return g.genPhone()
	}
}

// mixedDominantValues — Mongo mixed-типы с доминантой: ~60% значений —
// валидные строки доминирующего лейбла, остальное — числа, bool, null,
// json-фрагменты (как строки).
func (g *generator) mixedDominantValues(label verdict.Label) []string {
	out := make([]string, 0, g.rows)
	for i := 0; i < g.rows; i++ {
		if g.rng.IntN(100) < 60 {
			out = append(out, g.positiveValue(label))
		} else {
			out = append(out, g.mixedOther())
		}
	}
	return out
}

// mixedOther — «чужой» scalar-тип для mixed-колонки.
func (g *generator) mixedOther() string {
	switch g.rng.IntN(8) {
	case 0:
		return strconv.Itoa(g.rng.IntN(1000))
	case 1:
		return fmt.Sprintf("%d.%d", g.rng.IntN(100), g.rng.IntN(10))
	case 2:
		if g.rng.IntN(2) == 0 {
			return "true"
		}
		return "false"
	case 3:
		return "null"
	case 4:
		return g.genJSON()
	case 5:
		return g.genDate(2015, 2026)
	case 6:
		return g.genPersonName()
	default:
		return g.genBool()
	}
}

// chaosValues — Mongo mixed-типы без доминанты (label UNKNOWN): случайная
// смесь всего.
func (g *generator) chaosValues() []string {
	out := make([]string, 0, g.rows)
	for i := 0; i < g.rows; i++ {
		if g.rng.IntN(2) == 0 {
			out = append(out, g.positiveValue(dominantLabels[g.rng.IntN(len(dominantLabels))]))
		} else {
			out = append(out, g.mixedOther())
		}
	}
	return out
}

// polyValues — полиморфные коллекции Mongo (label UNKNOWN): JSON-массивы
// с разнотипными элементами и документы с разными схемами по значениям.
func (g *generator) polyValues() []string {
	out := make([]string, 0, g.rows)
	for i := 0; i < g.rows; i++ {
		out = append(out, g.polyValue())
	}
	return out
}

func (g *generator) polyValue() string {
	w := func() string { return jsonWords[g.rng.IntN(len(jsonWords))] }
	n := func() string { return strconv.Itoa(g.rng.IntN(1000)) }
	switch g.rng.IntN(6) {
	case 0:
		return fmt.Sprintf(`["%s",%s,true]`, w(), n())
	case 1:
		return fmt.Sprintf(`[%s,%s,%s]`, n(), n(), n())
	case 2:
		return fmt.Sprintf(`{"type":"a","v":%s}`, n())
	case 3:
		return fmt.Sprintf(`{"kind":"b","s":"%s"}`, w())
	case 4:
		return fmt.Sprintf(`{"id":%s,"items":[%s,%s],"flag":false}`, n(), n(), n())
	default:
		return fmt.Sprintf(`{"%s":{"%s":%s},"tags":["%s"]}`, w(), w(), n(), w())
	}
}
