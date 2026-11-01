// Тесты входа по admin-token при выключенном SSO (S9-8, З2, blueprint п. 12):
// страницы закрыты без сессии (GET → /login, POST → 403), /login выдаёт
// сессию admin, неверный токен — 403 без сессии, dev-режим без токена не меняется.
package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DunchikVlad/zond/internal/auth"
)

// noRedirect — клиент, не следующий редиректам (проверка 302 Location).
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func newTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, err := New(fixtureStore(t), nil, auth.NewSessionStore(0), false, nil, testBundle(),
		WithAdminToken("secret-token"))
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func postLogin(t *testing.T, client *http.Client, rawURL, token string) *http.Response {
	t.Helper()
	form := url.Values{"token": {token}, "csrf_token": {testCSRFToken}}
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: testCSRFToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", rawURL, err)
	}
	return resp
}

// TestTokenModePagesClosed — без сессии страницы закрыты: GET → 302 /login,
// POST → 403 (п. 12: режим без SSO — только admin-token).
func TestTokenModePagesClosed(t *testing.T) {
	ts := newTokenServer(t)
	c := noRedirect()
	resp, err := c.Get(ts.URL + "/scans")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET без сессии: %d, Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Админская страница — тоже закрыта.
	resp, err = c.Get(ts.URL + "/settings")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /settings без сессии: %d", resp.StatusCode)
	}
	// POST-мутация без сессии → 403 (не редирект).
	form := url.Values{"csrf_token": {testCSRFToken}}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/scans/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: testCSRFToken})
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST без сессии: %d", resp.StatusCode)
	}
}

// TestTokenModeLoginFlow — форма доступна анонимно; неверный токен → 403 без
// cookie; верный → 302 + сессия, дальше страницы открыты.
func TestTokenModeLoginFlow(t *testing.T) {
	ts := newTokenServer(t)
	c := noRedirect()

	resp, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("get /login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "admin-token") {
		t.Fatalf("форма входа: %d", resp.StatusCode)
	}

	// Неверный токен → 403, сессия не выдаётся.
	resp = postLogin(t, c, ts.URL+"/login", "wrong")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("неверный токен: %d", resp.StatusCode)
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == auth.SessionCookie {
			t.Fatalf("сессия на неверный токен выдана")
		}
	}

	// Верный токен → 302 на /scans + cookie сессии.
	resp = postLogin(t, c, ts.URL+"/login", "secret-token")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/scans" {
		t.Fatalf("верный токен: %d, Location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var sess *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == auth.SessionCookie {
			sess = ck
		}
	}
	if sess == nil || sess.Value == "" {
		t.Fatalf("cookie сессии не выдан")
	}

	// С сессией страница открывается.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/scans", nil)
	req.AddCookie(sess)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("get /scans: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /scans с сессией: %d", resp.StatusCode)
	}
}

// TestTokenModeLoginRateLimit — серия неверных токенов с одного IP → 429
// (brute-force блокировка входа, п. 14).
func TestTokenModeLoginRateLimit(t *testing.T) {
	ts := newTokenServer(t)
	c := noRedirect()
	var last int
	for i := 0; i < auth.LimiterMaxFails+1; i++ {
		resp := postLogin(t, c, ts.URL+"/login", "wrong")
		resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("после %d неудач ожидался 429, получен %d", auth.LimiterMaxFails+1, last)
	}
}

// TestDevModeUnchanged — без admin-token и SSO — прежний dev-режим (тесты):
// страницы открыты без сессии.
func TestDevModeUnchanged(t *testing.T) {
	srv, err := New(fixtureStore(t), nil, auth.NewSessionStore(0), false, nil, testBundle())
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	code, _ := get(t, ts.Client(), ts.URL+"/scans")
	if code != http.StatusOK {
		t.Fatalf("dev-режим: %d", code)
	}
}
