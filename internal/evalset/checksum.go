package evalset

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

// Конструкторы значений с контрольными суммами — зеркала алгоритмов
// recognizer'ов слоя 1 (internal/analyze/rules, blueprint п. 16.1).
// Позитивы датасета обязаны детектиться, спуфы — отвергаться; единый
// источник формул здесь, сверка с rules — в evalset_test.go.

// luhnValid — контрольная сумма Луна для строки цифр (как rules/luhn.go).
func luhnValid(digits []byte) bool {
	sum := 0
	parity := len(digits) % 2
	for i := 0; i < len(digits); i++ {
		n := int(digits[i] - '0')
		if i%2 == parity {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// makeLuhnDigits собирает n-значную строку цифр с валидной суммой Луна:
// body — произвольные цифры, последний разряд подобран под контрольную сумму.
func makeLuhnDigits(rng *rand.Rand, body string) string {
	d := []byte(body)
	for check := 0; check < 10; check++ {
		cand := append(append([]byte{}, d...), byte('0'+check))
		if luhnValid(cand) {
			return string(cand)
		}
	}
	// недостижимо: для любого тела ровно один check подходит
	panic("makeLuhnDigits: контрольный разряд не найден")
}

var innW10 = [...]int{2, 4, 10, 3, 5, 9, 4, 6, 8}
var innW11 = [...]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
var innW12 = [...]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}

// innCheck — взвешенная контрольная цифра: (Σ d[i]*w[i]) % 11 % 10.
func innCheck(digits []int, w []int) int {
	sum := 0
	for i, d := range digits {
		sum += d * w[i]
	}
	return sum % 11 % 10
}

// makeINN10 — валидный ИНН юрлица: 9 случайных цифр + контрольная (ФНС).
func makeINN10(rng *rand.Rand) string {
	d := make([]int, 9)
	d[0] = 1 + rng.IntN(9) // регион не начинается с 0 (правдоподобие)
	for i := 1; i < 9; i++ {
		d[i] = rng.IntN(10)
	}
	d = append(d, innCheck(d, innW10[:]))
	return digitsString(d)
}

// makeINN12 — валидный ИНН физлица: 10 случайных цифр + 2 контрольных (ФНС).
func makeINN12(rng *rand.Rand) string {
	d := make([]int, 10)
	d[0] = 1 + rng.IntN(9)
	for i := 1; i < 10; i++ {
		d[i] = rng.IntN(10)
	}
	d = append(d, innCheck(d[:10], innW11[:])) // 11-я цифра: контроль первых 10
	d = append(d, innCheck(d[:11], innW12[:])) // 12-я цифра: контроль первых 11
	return digitsString(d)
}

// makeSNILS — валидный СНИЛС: 9 случайных цифр + 2 контрольных (ПФР).
// Избегает недопустимой комбинации «все цифры одинаковые и первая '0'».
func makeSNILS(rng *rand.Rand) string {
	d := make([]int, 9)
	for i := range d {
		d[i] = rng.IntN(10)
	}
	if d[0] == 0 {
		same := true
		for _, v := range d {
			if v != 0 {
				same = false
				break
			}
		}
		if same {
			d[3] = 1
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
	d = append(d, check/10, check%10)
	return digitsString(d)
}

// makeIBAN — валидный IBAN (ISO 13616): код страны + 2 контрольные цифры
// (mod-97) + BBAN из [A-Z0-9]. Как rules/iban.go: перестановка BBAN+страна+00,
// остаток 97 → check = 98 − rem.
func makeIBAN(country, bban string) string {
	rem := ibanMod97(bban + country + "00")
	check := 98 - rem
	return fmt.Sprintf("%s%02d%s", country, check, bban)
}

// ibanMod97 — остаток от деления численного представления на 97; буквы
// разворачиваются в две цифры (A=10 … Z=35).
func ibanMod97(s string) int {
	rem := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			n := int(c-'A') + 10
			rem = (rem*100 + n) % 97
		}
	}
	return rem
}

// digitsString склеивает цифры в строку.
func digitsString(d []int) string {
	var b strings.Builder
	for _, v := range d {
		b.WriteByte(byte('0' + v))
	}
	return b.String()
}

// group4 — группы по 4 символа через пробел ("GB29 NWBK 6016 …").
func group4(s string) string {
	var b strings.Builder
	for i, c := range []byte(s) {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// corruptCheck меняет последний разряд на гарантированно иной — для спуфов
// с линейной контрольной суммой (ИНН, СНИЛС, Luhn) этого достаточно.
func corruptCheck(s string) string {
	b := []byte(s)
	last := b[len(b)-1]
	b[len(b)-1] = byte('0' + (int(last-'0')+1+int(len(s)))%10)
	return string(b)
}
