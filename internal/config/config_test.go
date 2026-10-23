package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("запись %s: %v", name, err)
	}
}

const validConnections = `
version: "1"
sources:
  - name: ch-prod
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
  - name: mongo-prod
    type: mongodb
    uri: "${CFG_TEST_URI}"
sso:
  enabled: false
`

const validDetectors = `
version: "1"
scan:
  profile: deep
  sample:
    mode: percent
    value: 5
    min_rows: 100
    max_rows: 20000
    max_string_chars: 200
    dedup_values: true
ensemble:
  tau_accept: 0.80
  tau_review: 0.50
  weights:
    meta: 1.0
    rules: 1.5
    llm: 1.2
agents:
  - id: main
    endpoint: https://llm.example/v1/chat
    model: gpt-4o-mini
    api_key_env: CFG_TEST_LLM_KEY
    max_values_per_call: 25
    timeout_s: 30
    max_retries: 3
    confidence_band: [0.30, 0.70]
    escalate_to: strong
  - id: strong
    endpoint: https://llm2.example/v1/chat
    model: gpt-4o
    api_key_env: CFG_TEST_LLM_KEY
    max_values_per_call: 25
    timeout_s: 60
    max_retries: 3
    confidence_band: [0.30, 0.70]
`

const validTaxonomy = `
version: "1.0.0"
labels:
  - {name: PHONE, sensitivity: PII}
  - {name: EMAIL, sensitivity: PII}
  - {name: NUMERIC_MEASURE, sensitivity: none}
`

func setValidEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"CFG_TEST_PWD":     "x",
		"CFG_TEST_URI":     "mongodb://x@h/db",
		"CFG_TEST_LLM_KEY": "x",
	} {
		t.Setenv(k, v)
	}
}

func validDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "connections.yaml", validConnections)
	writeFile(t, dir, "detectors.yaml", validDetectors)
	writeFile(t, dir, "taxonomy.yaml", validTaxonomy)
	return dir
}

func TestLoadAllValid(t *testing.T) {
	setValidEnv(t)
	b, err := LoadAll(validDir(t))
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(b.Connections.Sources) != 2 || len(b.Detectors.Agents) != 2 || len(b.Taxonomy.Labels) != 3 {
		t.Fatalf("неожиданные счётчики: %+v", b)
	}
	if b.Taxonomy.Version != "1.0.0" {
		t.Fatalf("version: %q", b.Taxonomy.Version)
	}
}

func TestCommentWithDollarNotExpanded(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
# комментарий с ${NOT_A_REAL_VAR} не должен трогать интерполяцию
version: "1"
sources:
  - name: ch-test
    type: clickhouse
    dsn: "clickhouse://ro:${CFG_TEST_PWD}@h:9000/db"
`)
	c, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
	if err != nil {
		t.Fatalf("комментарий с ${VAR} сломал загрузку: %v", err)
	}
	if c.Sources[0].DSN != "clickhouse://ro:x@h:9000/db" {
		t.Fatalf("DSN не интерполирован: %q", c.Sources[0].DSN)
	}
}

func TestConnectionsUnknownFieldRejected(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", "version: \"1\"\nsources: []\nunknown_key: 1\n")
	if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err == nil {
		t.Fatal("неизвестное поле должно отклоняться (строгая схема)")
	}
}

func TestConnectionsMissingEnvListed(t *testing.T) {
	t.Setenv("CFG_TEST_URI", "mongodb://x@h/db")
	t.Setenv("CFG_TEST_LLM_KEY", "x") // для detectors, не для этого кейса
	dir := validDir(t)
	_, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
	if err == nil || !strings.Contains(err.Error(), "CFG_TEST_PWD") {
		t.Fatalf("ожидалась ошибка с именем переменной, получено: %v", err)
	}
}

func TestConnectionsDuplicateSource(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - {name: a, type: clickhouse, dsn: "x"}
  - {name: a, type: mongodb, uri: "y"}
`)
	if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err == nil {
		t.Fatal("дубль имени источника должен отклоняться")
	}
}

func TestConnectionsDSNorURIExclusive(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - {name: a, type: clickhouse}
`)
	if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err == nil {
		t.Fatal("источник без dsn и uri должен отклоняться")
	}
}

func TestDetectorsBadConfidenceBand(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	bad := strings.Replace(validDetectors, "confidence_band: [0.30, 0.70]", "confidence_band: [0.8, 0.3]", 1)
	writeFile(t, dir, "detectors.yaml", bad)
	if _, err := LoadDetectors(filepath.Join(dir, "detectors.yaml")); err == nil {
		t.Fatal("перевёрнутый confidence_band должен отклоняться")
	}
}

func TestDetectorsEscalateToUnknown(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	bad := strings.Replace(validDetectors, "escalate_to: strong", "escalate_to: ghost", 1)
	writeFile(t, dir, "detectors.yaml", bad)
	if _, err := LoadDetectors(filepath.Join(dir, "detectors.yaml")); err == nil {
		t.Fatal("escalate_to на несуществующего агента должен отклоняться")
	}
}

func TestDetectorsTauOrdering(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	bad := strings.Replace(validDetectors, "tau_review: 0.50", "tau_review: 0.95", 1)
	writeFile(t, dir, "detectors.yaml", bad)
	if _, err := LoadDetectors(filepath.Join(dir, "detectors.yaml")); err == nil {
		t.Fatal("tau_review >= tau_accept должен отклоняться")
	}
}

func TestTaxonomyBadSensitivity(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "taxonomy.yaml", `
version: "1.0.0"
labels:
  - {name: PHONE, sensitivity: SECRET}
`)
	if _, err := LoadTaxonomy(filepath.Join(dir, "taxonomy.yaml")); err == nil {
		t.Fatal("неизвестная sensitivity должна отклоняться")
	}
}

func TestTaxonomyDuplicateLabel(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "taxonomy.yaml", `
version: "1.0.0"
labels:
  - {name: PHONE, sensitivity: PII}
  - {name: PHONE, sensitivity: none}
`)
	if _, err := LoadTaxonomy(filepath.Join(dir, "taxonomy.yaml")); err == nil {
		t.Fatal("дубль лейбла должен отклоняться")
	}
}

// TestConnectionsBackupScheduleRequiresDir — расписание бэкапов без каталога
// отклоняется (п. 15.2: копии — вне инстанса).
func TestConnectionsBackupScheduleRequiresDir(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources: []
backup: {schedule: "0 3 * * *"}
`)
	if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err == nil {
		t.Fatal("backup.schedule без backup.dir должен отклоняться")
	}
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources: []
backup: {schedule: "0 3 * * *", dir: "/var/backups/zond"}
`)
	if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err != nil {
		t.Fatalf("корректный backup отклонён: %v", err)
	}
}

// TestConnectionsVaultValid — источник с ref + корректный блок vault
// (ADR-0012): kv-v2 (key) и dynamic (dsn_template с обоими плейсхолдерами).
func TestConnectionsVaultValid(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
  - {name: mongo-prod, type: mongodb, ref: mongo-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: database/creds/ch-prod-readonly, dsn_template: "clickhouse://{{username}}:{{password}}@ch:9000/db"}
    - {ref: mongo-prod, path: kv/data/zond/mongo-prod, key: uri}
`)
	c, err := LoadConnections(filepath.Join(dir, "connections.yaml"))
	if err != nil {
		t.Fatalf("валидный vault-конфиг отклонён: %v", err)
	}
	if c.Sources[0].Ref != "ch-prod" || c.Vault.Secrets[0].DSNTemplate == "" {
		t.Fatalf("ref/dsn_template не распарсены: %+v", c)
	}
}

// TestConnectionsVaultInvalid — таблица некорректных vault-конфигов
// (fail-fast, п. 12.1): каждый случай — отдельная правка валидного блока.
func TestConnectionsVaultInvalid(t *testing.T) {
	valid := `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: database/creds/ch-prod-readonly, dsn_template: "clickhouse://{{username}}:{{password}}@ch:9000/db"}
`
	cases := map[string]string{
		"ref без vault.enabled": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
`,
		"блок настроен, но enabled=false": valid + "\n" + `vault:
  enabled: false
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: p, key: uri}
`,
		"нет address": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: p, key: uri}
`,
		"method token без token_env": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token}
  secrets:
    - {ref: ch-prod, path: p, key: uri}
`,
		"неизвестный auth.method": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: ldap}
  secrets:
    - {ref: ch-prod, path: p, key: uri}
`,
		"источник указывает на несуществующую запись secrets": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: other, path: p, key: uri}
`,
		"запись secrets без источника": valid + "\n" + `vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ghost, path: p, key: uri}
`,
		"key и dsn_template вместе": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: p, key: uri, dsn_template: "clickhouse://{{username}}:{{password}}@ch/db"}
`,
		"dsn_template без плейсхолдеров": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: p, dsn_template: "clickhouse://ch:9000/db"}
`,
		"запись без key и без dsn_template": `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: ch-prod, path: p}
`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			setValidEnv(t)
			dir := validDir(t)
			writeFile(t, dir, "connections.yaml", cfg)
			if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err == nil {
				t.Fatalf("кейс %q: конфиг должен отклоняться", name)
			}
		})
	}
}

// TestConnectionsVaultTokenInConfigRejected — токен в конфиге отвергается
// строгим парсером (п. 12.1: токен — только env/JWT).
func TestConnectionsVaultTokenInConfigRejected(t *testing.T) {
	setValidEnv(t)
	dir := validDir(t)
	writeFile(t, dir, "connections.yaml", `
version: "1"
sources:
  - {name: ch-prod, type: clickhouse, ref: ch-prod}
vault:
  enabled: true
  address: "https://vault.example.com"
  auth: {method: token, token: "secret-in-config"}
  secrets:
    - {ref: ch-prod, path: p, key: uri}
`)
	if _, err := LoadConnections(filepath.Join(dir, "connections.yaml")); err == nil {
		t.Fatal("auth.token в конфиге должен отклоняться строгой схемой")
	}
}
