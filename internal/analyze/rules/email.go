package rules

import (
	"regexp"
	"strings"

	"github.com/DunchikVlad/zond/internal/verdict"
)

type emailRecognizer struct{}

func (emailRecognizer) ID() string           { return "rules/email" }
func (emailRecognizer) Label() verdict.Label { return verdict.Label("EMAIL") }
func (emailRecognizer) HasChecksum() bool    { return false }

var emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`)

func (emailRecognizer) Match(v string) bool {
	if len(v) > 254 || strings.Count(v, "@") != 1 {
		return false
	}
	at := strings.IndexByte(v, '@')
	if at == 0 || at > 64 {
		return false
	}
	if strings.Contains(v[:at], "..") || strings.Contains(v[at+1:], "..") {
		return false
	}
	return emailRe.MatchString(v)
}
