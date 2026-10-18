package rules

import (
	"net"
	"net/netip"
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// ipRecognizer — IPv4/IPv6-адрес (blueprint п. 16.1). Строгая валидация
// через netip (не regex), без портов и CIDR.
type ipRecognizer struct{}

func (ipRecognizer) ID() string           { return "rules/ip" }
func (ipRecognizer) Label() verdict.Label { return verdict.Label("IP_ADDRESS") }
func (ipRecognizer) HasChecksum() bool    { return false }

func (ipRecognizer) Match(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, "/:") && strings.Count(v, ":") < 2 {
		// отсекаем CIDR и "host:port" для IPv4
		return false
	}
	if strings.Count(v, ":") >= 2 {
		// IPv6 (в т.ч. с зоной fe80::1%eth0 отбрасываем — это не БД-значение)
		if strings.Contains(v, "%") {
			return false
		}
		_, err := netip.ParseAddr(v)
		return err == nil
	}
	// IPv4: net.ParseIP допускает и IPv6, но ":" уже исключены
	ip := net.ParseIP(v)
	return ip != nil && ip.To4() != nil
}
