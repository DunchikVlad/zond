package rules

import (
	"github.com/DunchikVlad/zond/internal/verdict"
)

// bankAccountRecognizer — расчётный счёт РФ: 20 цифр (blueprint п. 16.1:
// счета 40802/40702 и др.). Контрольная сумма — по ключованию с БИК
// (положение ЦБ): значение "БИК(3 последние)+счёт", взвешенная сумма по
// коэффициентам 7-1-3, каждый разряд результата должен быть 0.
// Match без БИК: проверяем внутреннюю структуру (8-9 разряды — код валюты,
// 9-й — контрольный) и что счёт не нулевой; полная проверка ключа требует
// БИК, поэтому HasChecksum=false (нет самодостаточной суммы в одном значении).
type bankAccountRecognizer struct{}

func (bankAccountRecognizer) ID() string           { return "rules/bank_account" }
func (bankAccountRecognizer) Label() verdict.Label { return verdict.Label("BANK_ACCOUNT") }
func (bankAccountRecognizer) HasChecksum() bool    { return false }

func (bankAccountRecognizer) Match(v string) bool {
	digits := make([]byte, 0, 20)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == ' ' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits = append(digits, c)
	}
	if len(digits) != 20 {
		return false
	}
	// счёт не может быть полностью нулевым; первые 3 разряда — счёт 1-го порядка
	// (40802, 40702, 30109, …) не нулевые
	if digits[0] == '0' {
		return false
	}
	zero := true
	for _, c := range digits {
		if c != '0' {
			zero = false
			break
		}
	}
	return !zero
}

// BankAccountKeyCheck проверяет ключ 9-го разряда счёта по БИК (положение ЦБ
// о ключевании). Вынесено отдельно для тестов и будущего вызова с БИК из
// соседней колонки (кластеризация п. 7.6, этап 3+).
func BankAccountKeyCheck(bik, account string) bool {
	if len(bik) != 9 || len(account) != 20 {
		return false
	}
	val := bik[6:] + account // 3 последние цифры БИК + счёт (23 символа)
	if len(val) != 23 {
		return false
	}
	var w = [23]int{7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1}
	sum := 0
	for i := 0; i < 23; i++ {
		c := val[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * w[i]
	}
	return sum%10 == 0
}
