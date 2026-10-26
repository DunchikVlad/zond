// Тесты S9-3: нормализация и хэш пользовательской инструкции, промпт с
// блоком operator_instruction (контракт blueprint S9 п. 4).
package prompts

import (
	"strings"
	"testing"
)

func TestNormalizeUser(t *testing.T) {
	// пустое и пробельное — стандартный промпт
	for _, s := range []string{"", "   ", "\n\t "} {
		got, err := NormalizeUser(s)
		if err != nil || got != "" {
			t.Fatalf("NormalizeUser(%q) = %q, %v; ожидалось \"\", nil", s, got, err)
		}
	}
	// края обрезаются
	got, err := NormalizeUser("  медицинская БД  ")
	if err != nil || got != "медицинская БД" {
		t.Fatalf("trim: %q, %v", got, err)
	}
	// ровно лимит — проходит
	edge := strings.Repeat("а", MaxUserInstructionRunes)
	if got, err = NormalizeUser(edge); err != nil || len([]rune(got)) != MaxUserInstructionRunes {
		t.Fatalf("граница лимита: %v", err)
	}
	// лимит + 1 — отказ
	if _, err = NormalizeUser(edge + "б"); err == nil {
		t.Fatal("сверхлимитная инструкция принята")
	}
	// NUL — отказ
	if _, err = NormalizeUser("инструкция\x00скрытая"); err == nil {
		t.Fatal("инструкция с NUL принята")
	}
}

func TestUserHash(t *testing.T) {
	if got := UserHash(""); got != "" {
		t.Fatalf("пустой хэш = %q, ожидалось \"\"", got)
	}
	a := UserHash("контекст А")
	b := UserHash("контекст Б")
	if a == "" || a == b {
		t.Fatalf("хэши не различают инструкции: %q vs %q", a, b)
	}
	if again := UserHash("контекст А"); again != a {
		t.Fatal("UserHash недетерминирован")
	}
	// контракт: UserHash хэширует уже нормализованную строку как есть;
	// нормализация (trim) — обязанность вызывающей стороны (NormalizeUser).
	if UserHash(" контекст А ") == a {
		t.Fatal("UserHash не должен молча нормализовать вход")
	}
}

func TestSystemWithInstruction(t *testing.T) {
	labels := []string{"EMAIL", "UNKNOWN"}
	base := System(labels)
	full := SystemWithInstruction(labels, "это медицинская БД")

	if !strings.Contains(full, base) {
		t.Fatal("защищённый базовый промпт не сохранён целиком")
	}
	if !strings.Contains(full, "это медицинская БД") {
		t.Fatal("инструкция не попала в промпт")
	}
	// фиксация неотменяемости правил — часть контракта S9-3
	if !strings.Contains(full, "НЕ\nотменяет") || !strings.Contains(full, "<operator_instruction>") {
		t.Fatal("блок operator_instruction искажён")
	}
	// enum лейблов на месте
	if !strings.Contains(full, "EMAIL, UNKNOWN") {
		t.Fatal("enum лейблов потерян")
	}
}

func TestVerifierSystemWithInstruction(t *testing.T) {
	full := VerifierSystemWithInstruction([]string{"PHONE"}, "контекст")
	if !strings.Contains(full, VerifierSystem([]string{"PHONE"})) || !strings.Contains(full, "контекст") {
		t.Fatal("инструкция верификатора искажена")
	}
}
