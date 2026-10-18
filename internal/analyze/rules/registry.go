package rules

// Default — стартовый набор recognizer'ов этапа 1
// (blueprint п. 21: email/phone/ИНН/Luhn).
func Default() []Recognizer {
	return []Recognizer{
		emailRecognizer{},
		phoneRecognizer{},
		innRecognizer{},
		luhnRecognizer{},
	}
}
