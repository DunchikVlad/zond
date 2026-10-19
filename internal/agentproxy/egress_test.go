package agentproxy

import (
	"strings"
	"testing"
)

// Табличные тесты egress-политики (blueprint п. 10.7). Только IP-литералы и
// localhost — без внешнего DNS и сети.

func TestCheckEgress(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		policy   Policy
		wantErr  bool
	}{
		{
			name:     "loopback разрешён",
			endpoint: "http://127.0.0.1:11434",
			policy:   Policy{},
		},
		{
			name:     "RFC 1918 10/8 разрешён",
			endpoint: "http://10.0.0.5",
			policy:   Policy{},
		},
		{
			name:     "RFC 1918 192.168/16 разрешён",
			endpoint: "http://192.168.1.1",
			policy:   Policy{},
		},
		{
			name:     "RFC 1918 172.16/12 разрешён",
			endpoint: "http://172.16.0.1",
			policy:   Policy{},
		},
		{
			name:     "публичный IP без allowlist запрещён",
			endpoint: "https://203.0.113.10",
			policy:   Policy{},
			wantErr:  true,
		},
		{
			name:     "публичный IP с CIDR-записью разрешён",
			endpoint: "https://203.0.113.10",
			policy:   Policy{Allowlist: []string{"203.0.113.10/32"}},
		},
		{
			name:     "публичный IP с IP-записью разрешён",
			endpoint: "https://203.0.113.10",
			policy:   Policy{Allowlist: []string{"203.0.113.10"}},
		},
		{
			name:     "hostname-запись: localhost",
			endpoint: "http://localhost:8080",
			policy:   Policy{Allowlist: []string{"localhost"}},
		},
		{
			name:     "offline: loopback запрещён",
			endpoint: "http://127.0.0.1:11434",
			policy:   Policy{Offline: true},
			wantErr:  true,
		},
		{
			name:     "offline: RFC 1918 запрещён",
			endpoint: "http://10.0.0.5",
			policy:   Policy{Offline: true},
			wantErr:  true,
		},
		{
			name:     "offline + allowlist-запись разрешён",
			endpoint: "http://127.0.0.1:11434",
			policy:   Policy{Offline: true, Allowlist: []string{"127.0.0.1/32"}},
		},
		{
			name:     "offline: чужая allowlist-запись не спасает публичный адрес",
			endpoint: "https://203.0.113.10",
			policy:   Policy{Offline: true, Allowlist: []string{"198.51.100.0/24"}},
			wantErr:  true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckEgress(c.endpoint, c.policy)
			if c.wantErr && err == nil {
				t.Fatalf("CheckEgress(%q, %+v) должна вернуть ошибку", c.endpoint, c.policy)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("CheckEgress(%q, %+v): %v", c.endpoint, c.policy, err)
			}
			if c.wantErr && err != nil && !strings.Contains(err.Error(), "п. 10.7") {
				t.Fatalf("ошибка должна ссылаться на п. 10.7: %v", err)
			}
		})
	}
}

// TestCheckEgressBadURL — endpoint без host / не парсится → запрещено (fail-closed).
func TestCheckEgressBadURL(t *testing.T) {
	for _, endpoint := range []string{"", "://noparse", "/relative/path"} {
		if err := CheckEgress(endpoint, Policy{}); err == nil {
			t.Fatalf("CheckEgress(%q) должна вернуть ошибку", endpoint)
		}
	}
}

// TestNewValidatesEgress — конструктор всегда проверяет эндпоинт по
// egress-политике (п. 10.7, fail-fast): нулевая Policy — базовая политика
// пункта (private/loopback разрешены, публичный адрес — нет); allowlist и
// offline её ужесточают.
func TestNewValidatesEgress(t *testing.T) {
	agent := testAgent("https://203.0.113.10")
	if _, err := New(agent, testLabels, "1.0.0"); err == nil {
		t.Fatal("базовая политика (п. 10.7) должна запретить публичный эндпоинт")
	}
	if _, err := New(agent, testLabels, "1.0.0", WithPolicy(Policy{Allowlist: []string{"203.0.113.10/32"}})); err != nil {
		t.Fatalf("allowlist-запись должна пропускать публичный эндпоинт: %v", err)
	}
	if _, err := New(agent, testLabels, "1.0.0", WithPolicy(Policy{Offline: true})); err == nil {
		t.Fatal("offline без allowlist должен запретить публичный эндпоинт")
	}
}
