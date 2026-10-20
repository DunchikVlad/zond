package auth_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/DunchikVlad/zond/internal/api"
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// E2E SSO-флоу против Keycloak в testcontainers (blueprint п. 16.5,
// инкремент 5в-5): SP-initiated login → ACS → сессия zond_session →
// API от имени sso:<subject> с ролью из assertion; JIT-запись в users;
// аудит sso_login_success. Требует docker; иначе skip.

func startKeycloak(t *testing.T) (baseURL string, term func()) {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:25.0.6",
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "kcadmin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "kcadmin",
		},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      filepath.Join("..", "..", "deploy", "keycloak", "realm-zond.json"),
			ContainerFilePath: "/opt/keycloak/data/import/realm-zond.json",
			FileMode:          0o644,
		}},
		Cmd:        []string{"start-dev", "--import-realm"},
		WaitingFor: wait.ForHTTP("/realms/zond").WithPort("8080/tcp").WithStartupTimeout(3 * time.Minute),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatalf("keycloak container: %v", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	port, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return "http://" + host + ":" + port.Port(), func() { _ = c.Terminate(ctx) }
}

var (
	reFormAction = regexp.MustCompile(`(?i)<form[^>]*\saction="([^"]+)"`)
	reFormInput  = regexp.MustCompile(`(?i)<input[^>]*\sname="([^"]+)"[^>]*\svalue="([^"]*)"`)
)

// submitPage — браузерный шаг: страница с формой → POST формы.
// Возвращает тело ответа после автоматического следования редиректам.
func submitPage(t *testing.T, client *http.Client, page string, fields map[string]string, extra map[string]string) string {
	t.Helper()
	action, vals := parseForm(t, page)
	for k, v := range extra {
		vals.Set(k, v)
	}
	for k, v := range fields {
		vals.Set(k, v)
	}
	resp, err := client.PostForm(action, vals)
	if err != nil {
		t.Fatalf("post %s: %v", action, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// parseForm — action и hidden-поля первой формы страницы.
func parseForm(t *testing.T, page string) (string, url.Values) {
	t.Helper()
	m := reFormAction.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("форма не найдена на странице: %.300q", page)
	}
	vals := url.Values{}
	for _, in := range reFormInput.FindAllStringSubmatch(page, -1) {
		vals.Set(in[1], html.UnescapeString(in[2]))
	}
	return html.UnescapeString(m[1]), vals
}

// ssoLogin — полный SP-initiated флоу: /saml/login → Keycloak → ACS →
// cookie zond_session в jar. Возвращает jar клиента.
func ssoLogin(t *testing.T, spURL, login, password string) *cookiejar.Jar {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	resp, err := client.Get(spURL + "/saml/login")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginPage, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница входа IdP: %d", resp.StatusCode)
	}
	// Форма входа Keycloak: username/password; hidden-поля (execution и пр.).
	afterCreds := submitPage(t, client, string(loginPage), map[string]string{
		"username": login, "password": password,
	}, nil)
	// Keycloak (POST binding) отдаёт auto-submit форму с SAMLResponse.
	if !strings.Contains(afterCreds, "SAMLResponse") {
		t.Fatalf("SAMLResponse-форма не получена: %.300q", afterCreds)
	}
	action, vals := parseForm(t, afterCreds)
	resp, err = client.PostForm(action, vals)
	if err != nil {
		t.Fatalf("acs: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("acs: %d", resp.StatusCode)
	}
	found := false
	for _, c := range jar.Cookies(mustURL(t, spURL)) {
		if c.Name == auth.SessionCookie && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("cookie zond_session не установлена после ACS")
	}
	return jar
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestSSOAgainstKeycloak(t *testing.T) {
	idpBase, term := startKeycloak(t)
	defer term()
	ctx := context.Background()

	metadataXML, err := auth.FetchMetadata(idpBase+"/realms/zond/protocol/saml/descriptor", "", nil)
	if err != nil {
		t.Fatalf("метаданные IdP: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "sso.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	sessions := auth.NewSessionStore(0)

	// Сервер создаём незапущенным: ACS URL из его адреса нужен конфигу SP.
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	hooks := auth.Hooks{
		UpsertUser: func(ctx context.Context, rec auth.UserRec) error {
			return st.UpsertUser(ctx, &store.User{
				Subject: rec.Subject, DisplayName: rec.DisplayName,
				Role: string(rec.Role), LastLoginAt: time.Now().UTC(),
			}, time.Now().UTC())
		},
		Audit: func(ctx context.Context, actor, action, target string, d map[string]any) error {
			return st.AppendAudit(ctx, []audit.Event{{
				Actor: actor, Category: audit.CatAuth, Action: action,
				Target: target, Details: d, TS: time.Now().UTC(),
			}})
		},
	}
	sp, err := auth.NewSP(auth.SAMLConfig{
		ACSURL:        srv.URL + "/saml/acs",
		RoleAttribute: "Role",
		MetadataXML:   metadataXML,
	}, sessions, hooks)
	if err != nil {
		t.Fatalf("NewSP: %v", err)
	}
	srv.Config.Handler = api.New(st, nil,
		api.WithAuth(api.AuthConfig{Enabled: true, Sessions: sessions}),
		api.WithSAML(sp.Handler()),
	).Handler()
	srv.Start()
	defer srv.Close()

	clientFor := func(jar *cookiejar.Jar) *http.Client {
		return &http.Client{Jar: jar, Timeout: 30 * time.Second}
	}
	get := func(t *testing.T, jar *cookiejar.Jar, path string) int {
		t.Helper()
		resp, err := clientFor(jar).Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// admin: вход → просмотр разрешён (роль admin).
	adminJar := ssoLogin(t, srv.URL, "admin", "admin123")
	if code := get(t, adminJar, "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("admin GET /api/v1/scans: %d", code)
	}
	u, err := st.GetUser(ctx, "admin")
	if err != nil || u == nil || u.Role != "admin" {
		t.Fatalf("JIT admin: %+v, %v", u, err)
	}

	// viewer: вход → просмотр есть, мутация запрещена (RBAC п. 11.3).
	viewerJar := ssoLogin(t, srv.URL, "viewer", "viewer123")
	if code := get(t, viewerJar, "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("viewer GET /api/v1/scans: %d", code)
	}
	uv, err := st.GetUser(ctx, "viewer")
	if err != nil || uv == nil || uv.Role != "viewer" {
		t.Fatalf("JIT viewer: %+v, %v", uv, err)
	}
	post, err := clientFor(viewerJar).Post(srv.URL+"/api/v1/scans", "application/json", strings.NewReader(`{"source":"ch-prod"}`))
	if err != nil {
		t.Fatalf("post scans: %v", err)
	}
	_, _ = io.ReadAll(post.Body)
	_ = post.Body.Close()
	if post.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer POST /api/v1/scans: %d, ожидался 403", post.StatusCode)
	}

	// Аудит входов: два sso_login_success от sso:admin / sso:viewer.
	entries, err := st.AuditList(ctx, audit.Filter{Category: audit.CatAuth})
	if err != nil {
		t.Fatalf("аудит: %v", err)
	}
	byActor := map[string]bool{}
	for _, e := range entries {
		if e.Action == "sso_login_success" {
			byActor[e.Actor] = true
		}
	}
	if !byActor["sso:admin"] || !byActor["sso:viewer"] {
		t.Fatalf("акторы входов: %v (всего записей auth: %d)", byActor, len(entries))
	}
	rep, err := st.AuditVerify(ctx)
	if err != nil || !rep.OK() {
		t.Fatalf("hash-chain: %+v, %v", rep, err)
	}
}
