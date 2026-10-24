package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadConnections — устойчивость парсера YAML-конфига (blueprint
// п. 16.10: YAML-конфига). Инварианты: загрузка не паникует; невалидный
// ввод отклоняется ошибкой (fail-fast), валидный — проходит. Секреты не
// интерполируются: ${VAR} без значения — ошибка (fail-fast, п. 12).
func FuzzLoadConnections(f *testing.F) {
	seeds := []string{
		"version: \"1\"\nsources: []\n",
		"version: \"1\"\nsources:\n  - {name: ch, type: clickhouse, dsn: \"clickhouse://h:9000/d\"}\n",
		"version: \"1\"\nsources: []\naudit:\n  sink: {kind: json-tcp, address: \"siem:5140\"}\n",
		"version: \"1\"\nsources: []\nbackup: {schedule: \"0 3 * * *\"}\n",
		"not yaml at all",
		"",
		"version: 1\nsources: [{}]\n",
		"version: \"1\"\nsources:\n  - {name: ch, type: clickhouse, dsn: \"${NO_SUCH_ENV}\"}\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "connections.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("запись: %v", err)
		}
		// Не должно паниковать; исход (загружен/ошибка) определяется
		// валидностью — обе ветки допустимы, паника — нет.
		_, _ = LoadConnections(path)
	})
}

// FuzzLoadDetectors — то же для detectors.yaml (пороги/агенты/лимиты).
func FuzzLoadDetectors(f *testing.F) {
	seeds := []string{
		"version: \"1\"\nscan: {profile: quick}\nensemble: {tau_accept: 0.8, tau_review: 0.5}\n",
		"version: \"1\"\nscan: {sample: {mode: percent, value: 5}}\nproxy: {max_concurrent: 8}\n",
		"version: \"1\"\nagents:\n  - {id: a, endpoint: \"https://x/v1\", model: m, api_key_env: K}\n",
		"not yaml",
		"",
		"version: \"1\"\nproxy: {max_concurrent: -1}\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "detectors.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("запись: %v", err)
		}
		_, _ = LoadDetectors(path)
	})
}

// FuzzLoadTaxonomy — то же для taxonomy.yaml (лейблы/sensitivity/semver).
func FuzzLoadTaxonomy(f *testing.F) {
	seeds := []string{
		"version: \"1.0.0\"\nlabels:\n  - {name: EMAIL, sensitivity: PII}\n",
		"version: \"1.0.0\"\nlabels: []\n",
		"version: \"1\"\nlabels:\n  - {name: X, sensitivity: bad}\n",
		"not yaml",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "taxonomy.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("запись: %v", err)
		}
		_, _ = LoadTaxonomy(path)
	})
}
