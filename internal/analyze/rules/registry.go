package rules

// Default — полный regex-слой этапа 3 (blueprint п. 21, п. 16.1):
// checksum (ИНН/Luhn/СНИЛС/IBAN) + форматные (email/phone/паспорт/счёт/IP/дата/UUID).
func Default() []Recognizer {
	return []Recognizer{
		emailRecognizer{},
		phoneRecognizer{},
		innRecognizer{},
		snilsRecognizer{},
		passportRecognizer{},
		luhnRecognizer{},
		bankAccountRecognizer{},
		ibanRecognizer{},
		ipRecognizer{},
		dateRecognizer{},
		uuidRecognizer{},
	}
}
