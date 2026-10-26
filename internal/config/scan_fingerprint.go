package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
)

// ScanFingerprint хеширует эффективный снимок конфигурации, влияющий на скан.
// Пароль в DSN/URI исключается, поэтому его ротация не делает resume несовместимым.
func ScanFingerprint(b *Bundle, src *Source, profile string, useLLM bool) (string, error) {
	source := *src
	source.DSN = withoutPassword(source.DSN)
	source.URI = withoutPassword(source.URI)
	payload := struct {
		Detectors *Detectors `json:"detectors"`
		Taxonomy  *Taxonomy  `json:"taxonomy"`
		Source    Source     `json:"source"`
		Profile   string     `json:"profile"`
		LLM       bool       `json:"llm"`
	}{b.Detectors, b.Taxonomy, source, profile, useLLM}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func withoutPassword(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}
