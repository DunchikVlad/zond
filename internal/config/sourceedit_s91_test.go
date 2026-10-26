package config

import (
	"strings"
	"testing"
)

func TestSourceEntryStrictSecretsAndAddressModes(t *testing.T) {
	bad := []string{
		"clickhouse://u:plaintext${PW}@h/db",
		"clickhouse://u:${PW}plaintext@h/db",
		"clickhouse://u:${PW}${OTHER}@h/db",
		"clickhouse://u:${PW@h/db",
	}
	for _, dsn := range bad {
		se := SourceEntry{Name: "s", Type: "clickhouse", DSN: dsn}
		if err := se.Validate(); err == nil {
			t.Errorf("секрет принят: %s", dsn)
		}
	}
	good := []SourceEntry{
		{Name: "s", Type: "clickhouse", DSN: "${CH_DSN}"},
		{Name: "s", Type: "mongodb", URI: "${MONGO_URI}"},
		{Name: "s", Type: "clickhouse", Ref: "s", MaxConcurrentScans: 2, MaxConcurrentTables: 3, QueryTimeoutS: 30},
	}
	for _, se := range good {
		if err := se.Validate(); err != nil {
			t.Errorf("валидная запись отклонена %+v: %v", se, err)
		}
	}
}

func TestSourceEditorValidateAllFullSchema(t *testing.T) {
	fixtures := []string{
		"sources: []\n",
		"version: '1'\nsources:\n  - {name: dup, type: clickhouse, dsn: '${DSN}'}\n  - {name: dup, type: clickhouse, dsn: '${DSN}'}\n",
		"version: '1'\nsources:\n  - {name: s, type: clickhouse, dsn: '${DSN}', max_concurrent_scans: -1}\n",
	}
	for _, fixture := range fixtures {
		e := openEditor(t, fixture)
		if err := e.ValidateAll(); err == nil {
			t.Errorf("полная схема принята:\n%s", fixture)
		}
	}
}

func TestSourceEditorVaultAndLimitsRoundTrip(t *testing.T) {
	fixture := `version: '1'
sources:
  - name: vault-db
    type: clickhouse
    ref: vault-db
vault:
  enabled: true
  address: http://127.0.0.1:8200
  auth: {method: token, token_env: VAULT_TOKEN}
  secrets:
    - {ref: vault-db, path: kv/db, key: dsn}
`
	e := openEditor(t, fixture)
	entry := SourceEntry{Name: "vault-db", Type: "clickhouse", Ref: "vault-db",
		MaxConcurrentScans: 2, MaxConcurrentTables: 3, QueryTimeoutS: 45}
	if err := e.Upsert(entry); err != nil {
		t.Fatal(err)
	}
	if err := e.ValidateAll(); err != nil {
		t.Fatal(err)
	}
	entries, err := e.Sources()
	if err != nil || len(entries) != 1 {
		t.Fatalf("Sources: %+v, %v", entries, err)
	}
	got := entries[0]
	if got.Ref != entry.Ref || got.DSN != "" || got.MaxConcurrentScans != 2 || got.MaxConcurrentTables != 3 || got.QueryTimeoutS != 45 {
		t.Fatalf("round-trip: %+v", got)
	}
	raw, _ := e.Bytes()
	for _, want := range []string{"max_concurrent_scans: 2", "max_concurrent_tables: 3", "query_timeout_s: 45"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("нет числового поля %q:\n%s", want, raw)
		}
	}
}
