// Egress-политика Agent Proxy (blueprint п. 10.7): allowlist по умолчанию пуст —
// разрешены только loopback и приватные диапазоны (RFC 1918); публичный
// эндпоинт — только явной записью в agents.*.allowlist. Флаг offline запрещает
// любые эндпоинты вне allowlist (включая loopback/RFC 1918). Закрывает SSRF
// из прокси наружу. Резолв — fail-closed: не разрешился host → вызов запрещён.
package agentproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// egressResolveTimeout — таймаут резолва host перед решением о допуске (п. 10.7).
const egressResolveTimeout = 5 * time.Second

// Policy — egress-политика для одного агента (blueprint п. 10.7). Нулевая
// Policy — базовая политика пункта: loopback/RFC 1918 разрешены, публичные
// адреса запрещены; Offline и Allowlist только ужесточают её. Проверка
// выполняется всегда (в конструкторе прокси), отключить её нельзя.
type Policy struct {
	Offline   bool     // true — запрещены любые эндпоинты вне allowlist
	Allowlist []string // IP, CIDR или hostname (регистронезависимо, без порта)
}

// CheckEgress проверяет эндпоинт по egress-политике (blueprint п. 10.7).
// Разрешено, если: host совпал с записью allowlist; либо (!Offline и все
// resolved IP приватные: loopback или RFC 1918/ULA). Иначе — ошибка.
func CheckEgress(endpoint string, p Policy) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("egress: эндпоинт %q не парсится: %w (п. 10.7)", endpoint, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("egress: в эндпоинте %q нет host (п. 10.7)", endpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), egressResolveTimeout)
	defer cancel()
	// net.Resolver: для IP-литералов резолв тривиален (без обращения к DNS).
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("egress: host %q не разрешился: %w (fail-closed, п. 10.7)", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("egress: host %q не разрешился в адреса (fail-closed, п. 10.7)", host)
	}
	ips := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			ips = append(ips, ip.Unmap()) // нормализация IPv4-mapped IPv6
		}
	}
	for _, entry := range p.Allowlist {
		if allowlistMatch(entry, host, ips) {
			return nil
		}
	}
	if p.Offline {
		return fmt.Errorf("egress: эндпоинт %q запрещён egress-политикой (offline: true, п. 10.7)", endpoint)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		return fmt.Errorf("egress: эндпоинт %q запрещён egress-политикой (blueprint п. 10.7): %s не loopback/RFC 1918 и не в allowlist", endpoint, ip)
	}
	return nil
}

// allowlistMatch — запись как IP/CIDR совпадает по любому resolved IP; иначе —
// hostname: регистронезависимое сравнение с host URL без порта.
func allowlistMatch(entry, host string, ips []netip.Addr) bool {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		for _, ip := range ips {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if addr, err := netip.ParseAddr(entry); err == nil {
		for _, ip := range ips {
			if addr.Unmap() == ip {
				return true
			}
		}
		return false
	}
	return strings.EqualFold(entry, host)
}
