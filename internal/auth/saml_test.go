package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml"
)

// Тесты SAML SP (инкремент 5в-5) без внешнего IdP: построение SP,
// sessionProvider (cookie/сессия/JIT/аудит), маппинг ролей, SLO-разбор.

// idpMetadataFixture — минимальные валидные метаданные IdP для crewjam.
const idpMetadataFixture = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="https://idp.example.com/realms/zond">
  <IDPSSODescriptor WantAuthnRequestsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/00/xmldsig#">
        <X509Data><X509Certificate>Zm9v</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example.com/realms/zond/protocol/saml"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://idp.example.com/realms/zond/protocol/saml/logout"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://idp.example.com/realms/zond/protocol/saml/logout/post"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func testSAMLConfig() SAMLConfig {
	return SAMLConfig{
		EntityID:      "https://zond.example.com/saml/metadata",
		ACSURL:        "https://zond.example.com/saml/acs",
		RoleAttribute: "Role",
		MetadataXML:   []byte(idpMetadataFixture),
	}
}

func TestNewSPBuildsWithEphemeralCert(t *testing.T) {
	var audited []string
	sp, err := NewSP(testSAMLConfig(), NewSessionStore(0), Hooks{
		Audit: func(ctx context.Context, actor, action, target string, details map[string]any) error {
			audited = append(audited, action)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewSP: %v", err)
	}
	if sp.m.Load() == nil {
		t.Fatal("middleware не построен")
	}
	found := false
	for _, a := range audited {
		if a == "sso_ephemeral_cert" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ephemeral-сертификат не зааудирован: %v", audited)
	}
}

func TestNewSPFailsOnBadACS(t *testing.T) {
	cfg := testSAMLConfig()
	cfg.ACSURL = "https://zond.example.com/wrong/acs"
	if _, err := NewSP(cfg, NewSessionStore(0), Hooks{}); err == nil {
		t.Fatal("ACS без суффикса /saml/acs должен быть отвергнут")
	}
	cfg.ACSURL = "not-a-url"
	if _, err := NewSP(cfg, NewSessionStore(0), Hooks{}); err == nil {
		t.Fatal("невалидный acs_url должен быть отвергнут")
	}
}

func TestBaseFromACS(t *testing.T) {
	u, err := baseFromACS("https://zond.example.com/saml/acs")
	if err != nil || u.String() != "https://zond.example.com/" {
		t.Fatalf("base: %v, %v", u, err)
	}
}

// sessionProvider.CreateSession: JIT + сессия + cookie + аудит входа.
func TestSessionProviderCreateSession(t *testing.T) {
	sessions := NewSessionStore(0)
	var jit UserRec
	var audited []string
	sp, err := NewSP(testSAMLConfig(), sessions, Hooks{
		UpsertUser: func(ctx context.Context, rec UserRec) error { jit = rec; return nil },
		Audit: func(ctx context.Context, actor, action, target string, d map[string]any) error {
			audited = append(audited, action)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewSP: %v", err)
	}
	assertion := &saml.Assertion{
		Subject: &saml.Subject{NameID: &saml.NameID{
			Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", Value: "ivan@example.com"}},
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{Name: "Role", Values: []saml.AttributeValue{{Value: "admin"}}},
				{Name: "displayName", Values: []saml.AttributeValue{{Value: "Иван"}}},
			},
		}},
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	rec := httptest.NewRecorder()
	if err := (&sessionProvider{sp: sp}).CreateSession(rec, req, assertion); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if jit.Subject != "ivan@example.com" || jit.Role != RoleAdmin || jit.DisplayName != "Иван" {
		t.Fatalf("JIT искажён: %+v", jit)
	}
	cookies := rec.Result().Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == SessionCookie {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("cookie сессии не установлена")
	}
	if !sessCookie.HttpOnly || sessCookie.SameSite != http.SameSiteLaxMode || sessCookie.Path != "/" {
		t.Fatalf("флаги cookie нарушены: %+v", sessCookie)
	}
	if _, ok := sessions.Get(sessCookie.Value); !ok {
		t.Fatal("сессия не создана в store")
	}
	if len(audited) == 0 || audited[len(audited)-1] != "sso_login_success" {
		t.Fatalf("аудит входа: %v", audited)
	}
}

// mapRole: атрибут ролей и группы; максимальная роль; default viewer.
func TestMapRole(t *testing.T) {
	mk := func(attrs ...saml.Attribute) *saml.Assertion {
		return &saml.Assertion{AttributeStatements: []saml.AttributeStatement{{Attributes: attrs}}}
	}
	cases := []struct {
		name string
		a    *saml.Assertion
		want Role
	}{
		{"роль admin из Role", mk(saml.Attribute{Name: "Role", Values: []saml.AttributeValue{{Value: "admin"}}}), RoleAdmin},
		{"роль viewer", mk(saml.Attribute{Name: "Role", Values: []saml.AttributeValue{{Value: "viewer"}}}), RoleViewer},
		{"max из нескольких", mk(saml.Attribute{Name: "Role", Values: []saml.AttributeValue{{Value: "viewer"}, {Value: "admin"}}}), RoleAdmin},
		{"группы путём", mk(saml.Attribute{Name: "groups", Values: []saml.AttributeValue{{Value: "/zond/admins"}}}), RoleAdmin},
		{"memberOf списком", mk(saml.Attribute{Name: "memberOf", Values: []saml.AttributeValue{{Value: "cn=zond viewers,ou=groups"}}}), RoleViewer},
		{"без ролей — viewer", mk(saml.Attribute{Name: "email", Values: []saml.AttributeValue{{Value: "x@y.z"}}}), RoleViewer},
		{"чужие значения игнор", mk(saml.Attribute{Name: "Role", Values: []saml.AttributeValue{{Value: "superuser"}}}), RoleViewer},
	}
	for _, c := range cases {
		if got := mapRole(c.a, "Role"); got != c.want {
			t.Errorf("%s: роль %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

// handleLogout: сессия удаляется, cookie инвалидируется, аудит, redirect
// на IdP SLO (MakeRedirectLogoutRequest).
func TestLogoutEndsSession(t *testing.T) {
	sessions := NewSessionStore(0)
	sp, err := NewSP(testSAMLConfig(), sessions, Hooks{
		Audit: func(ctx context.Context, actor, action, target string, d map[string]any) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewSP: %v", err)
	}
	sess := sessions.Create("ivan@example.com", RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/saml/logout", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: sess.ID})
	rec := httptest.NewRecorder()
	sp.handleLogout(rec, req)
	if _, ok := sessions.Get(sess.ID); ok {
		t.Fatal("сессия не удалена")
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("нет redirect на IdP SLO")
	}
	u, err := url.Parse(loc)
	if err != nil || !strings.Contains(u.String(), "idp.example.com") {
		t.Fatalf("redirect не на IdP: %q", loc)
	}
	if !u.Query().Has("SAMLRequest") {
		t.Fatal("SAMLRequest в redirect-логауте отсутствует")
	}
}

// handleSLO (IdP-initiated): LogoutRequest завершает сессии по NameID.
func TestSLOIdPInitiatedDeletesBySubject(t *testing.T) {
	sessions := NewSessionStore(0)
	sp, _ := NewSP(testSAMLConfig(), sessions, Hooks{})
	s1 := sessions.Create("ivan@example.com", RoleViewer)
	s2 := sessions.Create("ivan@example.com", RoleViewer)
	other := sessions.Create("petr@example.com", RoleViewer)

	logoutXML := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0" IssueInstant="2026-10-19T00:00:00Z"><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">ivan@example.com</saml:NameID></samlp:LogoutRequest>`
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(logoutXML))}}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	sp.handleSLO(rec, req)

	if _, ok := sessions.Get(s1.ID); ok {
		t.Fatal("сессия 1 не удалена SLO")
	}
	if _, ok := sessions.Get(s2.ID); ok {
		t.Fatal("сессия 2 не удалена SLO")
	}
	if _, ok := sessions.Get(other.ID); !ok {
		t.Fatal("чужая сессия удалена — недопустимо")
	}
}

// Handler: metadata отдаётся; login для анонима уходит в 302 на IdP.
func TestHandlerRoutes(t *testing.T) {
	sp, _ := NewSP(testSAMLConfig(), NewSessionStore(0), Hooks{})
	h := sp.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/metadata", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "entityID") {
		t.Fatalf("metadata: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login анонима: %d, ожидался 302 на IdP", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "idp.example.com") {
		t.Fatalf("login не ведёт на IdP: %q", loc)
	}
}

func TestSamlErrReasonNoResponseLeak(t *testing.T) {
	r := samlErrReason(&saml.InvalidResponseError{PrivateErr: context.DeadlineExceeded})
	if r != "context deadline exceeded" {
		t.Fatalf("причина: %q", r)
	}
}
