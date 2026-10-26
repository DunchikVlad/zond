package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
)

// ScanFingerprint хеширует эффективный снимок конфигурации, влияющий на скан.
// Пароль в DSN/URI исключается, поэтому его ротация не делает resume несовместимым.
// S9-3: promptHash — хэш пользовательской инструкции (сам текст не входит:
// хэш достаточен для различимости, а fingerprint не раздувается).
func ScanFingerprint(b *Bundle, src *Source, profile string, useLLM bool, promptHash string) (string, error) {
	source := *src
	source.DSN = withoutPassword(source.DSN)
	source.URI = withoutPassword(source.URI)
	payload := struct {
		Detectors  *Detectors `json:"detectors"`
		Taxonomy   *Taxonomy  `json:"taxonomy"`
		Source     Source     `json:"source"`
		Profile    string     `json:"profile"`
		LLM        bool       `json:"llm"`
		PromptHash string     `json:"prompt_hash"`
	}{b.Detectors, b.Taxonomy, source, profile, useLLM, promptHash}
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
