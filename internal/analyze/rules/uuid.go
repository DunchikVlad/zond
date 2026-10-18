package rules

import (
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

// uuidRecognizer — UUID RFC 4122: 8-4-4-4-12 hex, опционально в {…}
// (blueprint п. 16.1). Лейбл IDENTIFIER (objectId/uuid → словарь имён на meta).
type uuidRecognizer struct{}

func (uuidRecognizer) ID() string           { return "rules/uuid" }
func (uuidRecognizer) Label() verdict.Label { return verdict.Label("IDENTIFIER") }
func (uuidRecognizer) HasChecksum() bool    { return false }

func (uuidRecognizer) Match(v string) bool {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "{")
	v = strings.TrimSuffix(v, "}")
	if len(v) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := v[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
