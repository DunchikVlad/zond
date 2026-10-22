// DNS-резолв для doctor (net.DefaultResolver — тесты могут подменить).
package doctor

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"
)

// netResolver — тонкая обёртка над дефолтным резолвером (тесты подменяют
// lookupHost через переменную netDefaultResolver).
type netResolver struct{}

var netDefaultResolver = net.DefaultResolver

func (netResolver) lookupHost(ctx context.Context, host string) ([]string, error) {
	return netDefaultResolver.LookupHost(ctx, host)
}

// certInfo — читает PEM/DER-сертификат и проверяет срок действия на now.
func certInfo(path string, now time.Time) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("чтение %s: %w", path, err)
	}
	var cert *x509.Certificate
	if block, _ := pem.Decode(raw); block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
	} else {
		cert, err = x509.ParseCertificate(raw)
	}
	if err != nil {
		return "", fmt.Errorf("парсинг %s: %w", path, err)
	}
	if now.Before(cert.NotBefore) {
		return "", fmt.Errorf("сертификат ещё не действует (not before %s)", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return "", fmt.Errorf("сертификат истёк %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	days := int(cert.NotAfter.Sub(now).Hours() / 24)
	return fmt.Sprintf("действует до %s (~%d дн.), субъект %q",
		cert.NotAfter.UTC().Format(time.RFC3339), days, cert.Subject.CommonName), nil
}
