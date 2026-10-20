// SAML 2.0 Service Provider (инкремент 5в-5, ADR-0011, blueprint п. 11.3):
// crewjam/saml поверх внутренних SessionStore (cookie zond_session), JIT в
// users и аудита входов (п. 14.2). Поток: GET /saml/login стартует
// SP-initiated flow, POST /saml/acs принимает assertion (POST binding,
// проверка подписи и InResponseTo — crewjam), /saml/logout завершает сессию
// локально и шлёт IdP LogoutRequest (redirect, подписанный), /saml/slo
// принимает IdP-initiated logout. Метаданные IdP перечитываются каждые 24 ч
// (п. 11.3: ротация ключей IdP без рестарта).
package auth

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// UserRec — данные JIT-прvisioning (п. 11.3): запись users.
type UserRec struct {
	Subject     string // SAML NameID
	DisplayName string
	Role        Role
}

// Hooks — зависимости SP от инфраструктуры (пакет auth не импортирует
// store/audit напрямую; собирается в cmd/zond).
type Hooks struct {
	// UpsertUser — JIT: создать/обновить пользователя при входе (п. 11.3).
	UpsertUser func(ctx context.Context, rec UserRec) error
	// Audit — события auth: sso_login_success/failure, sso_logout, slo;
	// actor — формат п. 14.2 (sso:<subject> | saml | sso:unknown).
	Audit func(ctx context.Context, actor, action, target string, details map[string]any) error
	// Log — предупреждения (ephemeral-сертификат, неудача refresh метаданных).
	Log func(msg string, args ...any)
}

// SAMLConfig — параметры SP (публичный адрес — из sso:-блока connections.yaml;
// маршруты фиксированы /saml/*, развёртывание с path-префиксом не поддержано).
type SAMLConfig struct {
	EntityID       string // SP entityID (п. 11.3)
	ACSURL         string // публичный ACS, суффикс обязан быть /saml/acs
	NameIDFormat   string // например emailAddress (п. 12)
	RoleAttribute  string // атрибут с ролями (п. 11.3)
	CookieSameSite string // lax (default) | none (prod за TLS)
	KeyFile        string // PEM-ключ подписи SP; "" — ephemeral
	CertFile       string // PEM-сертификат SP; "" — ephemeral self-signed
	MetadataXML    []byte // метаданные IdP (загруженные до вызова)
}

// SP — SAML Service Provider: middleware crewjam + наши сессии/JIT/аудит.
// Middleware пересобирается при refresh метаданных и меняется атомарно.
type SP struct {
	cfg      SAMLConfig
	hooks    Hooks
	sess     *SessionStore
	key      crypto.Signer
	cert     *x509.Certificate
	nowFn    func() time.Time
	m        atomic.Pointer[samlsp.Middleware]
	samesite http.SameSite
}

// NewSP собирает SP: ключ/сертификат, парсинг метаданных IdP, middleware.
// Ошибка — fail-fast на старте serve (blueprint п. 11.3: метаданные IdP
// подтягиваются при старте).
func NewSP(cfg SAMLConfig, sess *SessionStore, hooks Hooks) (*SP, error) {
	if sess == nil {
		return nil, errors.New("auth: SessionStore обязателен для SP")
	}
	if _, err := baseFromACS(cfg.ACSURL); err != nil {
		return nil, err
	}
	if cfg.RoleAttribute == "" {
		return nil, errors.New("auth: role_attribute обязателен (п. 11.3)")
	}
	if len(cfg.MetadataXML) == 0 {
		return nil, errors.New("auth: метаданные IdP пусты")
	}
	sp := &SP{cfg: cfg, hooks: hooks, sess: sess, nowFn: time.Now,
		samesite: http.SameSiteLaxMode}
	if cfg.CookieSameSite == "none" {
		sp.samesite = http.SameSiteNoneMode
	}
	if err := sp.loadKeyCert(); err != nil {
		return nil, err
	}
	m, err := sp.buildMiddleware(cfg.MetadataXML)
	if err != nil {
		return nil, err
	}
	sp.m.Store(m)
	return sp, nil
}

// baseFromACS — публичный base URL SP из acs_url (путь — только /saml/acs).
func baseFromACS(acs string) (*url.URL, error) {
	u, err := url.Parse(acs)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("auth: acs_url %q невалиден (п. 12)", acs)
	}
	if !strings.HasSuffix(u.Path, "/saml/acs") {
		return nil, fmt.Errorf("auth: acs_url %q должен оканчиваться на /saml/acs", acs)
	}
	u.Path = strings.TrimSuffix(u.Path, "/saml/acs")
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// loadKeyCert — ключ/сертификат подписи SP из файлов конфигурации; при
// незаданных файлах — ephemeral self-signed (dev/демо) с предупреждением.
func (sp *SP) loadKeyCert() error {
	if sp.cfg.KeyFile != "" && sp.cfg.CertFile != "" {
		keyPEM, err := os.ReadFile(sp.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("auth: чтение sp_key_file: %w", err)
		}
		certPEM, err := os.ReadFile(sp.cfg.CertFile)
		if err != nil {
			return fmt.Errorf("auth: чтение sp_certificate_file: %w", err)
		}
		key, err := parseRSAKey(keyPEM)
		if err != nil {
			return err
		}
		certBlk, _ := pem.Decode(certPEM)
		if certBlk == nil {
			return errors.New("auth: sp_certificate_file не PEM")
		}
		cert, err := x509.ParseCertificate(certBlk.Bytes)
		if err != nil {
			return fmt.Errorf("auth: разбор sp_certificate_file: %w", err)
		}
		sp.key, sp.cert = key, cert
		return nil
	}
	// Ephemeral self-signed (п. 11.3: bootstrap; штатно — файлы из конфига).
	var serBytes [8]byte
	_, _ = rand.Read(serBytes[:])
	serial := new(big.Int).SetUint64(binary.LittleEndian.Uint64(serBytes[:]))
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "zond-sp-ephemeral", Organization: []string{"zond"}},
		NotBefore:             sp.nowFn().Add(-time.Hour),
		NotAfter:              sp.nowFn().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	sp.key, sp.cert = key, cert
	if sp.hooks.Log != nil {
		sp.hooks.Log("sso: sp_certificate_file/sp_key_file не заданы — ephemeral self-signed (dev/демо; prod — файлы, п. 11.3)")
	}
	_ = sp.audit(context.Background(), "saml", "sso_ephemeral_cert", "saml", map[string]any{"level": "warn"})
	return nil
}

func parseRSAKey(keyPEM []byte) (crypto.Signer, error) {
	keyBlk, _ := pem.Decode(keyPEM)
	if keyBlk == nil {
		return nil, errors.New("auth: sp_key_file не PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(keyBlk.Bytes); err == nil {
		return key, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(keyBlk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: разбор sp_key_file: %w", err)
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("auth: sp_key_file — не RSA-ключ")
	}
	return key, nil
}

// buildMiddleware — crewjam middleware с нашим sessionProvider и обёрткой
// ошибок ACS (аудит неудачных входов без утечки SAMLResponse).
func (sp *SP) buildMiddleware(metadataXML []byte) (*samlsp.Middleware, error) {
	idp, err := samlsp.ParseMetadata(metadataXML)
	if err != nil {
		return nil, fmt.Errorf("auth: разбор метаданных IdP: %w", err)
	}
	base, err := baseFromACS(sp.cfg.ACSURL)
	if err != nil {
		return nil, err
	}
	entityID := sp.cfg.EntityID
	if entityID == "" {
		entityID = base.String() + "saml/metadata"
	}
	m, err := samlsp.New(samlsp.Options{
		EntityID:           entityID,
		URL:                *base,
		Key:                sp.key,
		Certificate:        sp.cert,
		IDPMetadata:        idp,
		SignRequest:        true,
		CookieSameSite:     sp.samesite,
		DefaultRedirectURI: "/",
	})
	if err != nil {
		return nil, fmt.Errorf("auth: crewjam middleware: %w", err)
	}
	m.Session = &sessionProvider{sp: sp}
	m.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		// Провал входа/валидации — аудируемое событие (п. 14.2 auth);
		// SAMLResponse в ошибку НЕ включаем (ADR-0010: только причина).
		_ = sp.audit(r.Context(), "sso:unknown", "sso_login_failure", "saml", map[string]any{
			"reason": samlErrReason(err), "path": r.URL.Path,
		})
		http.Error(w, "SSO: вход не выполнен ("+samlErrReason(err)+")", http.StatusForbidden)
	}
	return m, nil
}

// samlErrReason — безопасная причина ошибки SAML: InvalidResponseError не
// содержит XML в Error(), внутреннюю причину обрезаем (п. 14.2, ADR-0010).
func samlErrReason(err error) string {
	var ivr *saml.InvalidResponseError
	if errors.As(err, &ivr) && ivr.PrivateErr != nil {
		return truncateRunes(ivr.PrivateErr.Error(), 160)
	}
	return truncateRunes(err.Error(), 160)
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Handler — маршруты SSO (монтируются под /saml/; вне withAuth — это точки
// входа для анонимного начала входа и приём ACS/SLO от IdP).
func (sp *SP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		sp.m.Load().ServeMetadata(w, r)
	})
	mux.HandleFunc("GET /saml/login", func(w http.ResponseWriter, r *http.Request) {
		// SP-initiated flow; после входа — на DefaultRedirectURI ("/").
		sp.m.Load().RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/", http.StatusFound)
		})).ServeHTTP(w, r)
	})
	mux.HandleFunc("POST /saml/acs", func(w http.ResponseWriter, r *http.Request) {
		sp.m.Load().ServeACS(w, r)
	})
	mux.HandleFunc("GET /saml/logout", sp.handleLogout)
	mux.HandleFunc("GET /saml/slo", sp.handleSLO)
	mux.HandleFunc("POST /saml/slo", sp.handleSLO)
	return mux
}

// handleLogout — локальный logout + SP-initiated SLO: сессия удаляется,
// браузер уходит на IdP SingleLogout (подписанный LogoutRequest, redirect).
func (sp *SP) handleLogout(w http.ResponseWriter, r *http.Request) {
	subject := ""
	if c, err := r.Cookie(SessionCookie); err == nil {
		if sess, ok := sp.sess.Get(c.Value); ok {
			subject = sess.Subject
		}
		sp.sess.Delete(c.Value)
	}
	sp.clearCookie(w, r)
	if subject != "" {
		_ = sp.audit(r.Context(), "sso:"+subject, "sso_logout", "sso:"+subject, map[string]any{"init": "sp"})
	}
	if subject == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	loc, err := sp.m.Load().ServiceProvider.MakeRedirectLogoutRequest(subject, "/")
	if err != nil {
		// IdP без SLO endpoint (редко) — локальный logout уже выполнен.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if u, perr := url.Parse(loc.String()); perr != nil || !u.IsAbs() {
		// IdP не публикует redirect-binding SLO — только локальный logout.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

// handleSLO — IdP-initiated logout (SAMLRequest=LogoutRequest) и ответ IdP
// на наш LogoutRequest (SAMLResponse). crewjam парсер не поставляет —
// разбор NameID минимальный (redirect: base64+deflate; POST: base64/xml).
func (sp *SP) handleSLO(w http.ResponseWriter, r *http.Request) {
	if req := r.FormValue("SAMLRequest"); req != "" {
		nameID, err := parseLogoutRequestNameID(req, r.Method == http.MethodGet)
		if err == nil && nameID != "" {
			sp.sess.DeleteBySubject(nameID)
			_ = sp.audit(r.Context(), "sso:"+nameID, "slo", "sso:"+nameID, map[string]any{"init": "idp"})
		}
	}
	if resp := r.FormValue("SAMLResponse"); resp != "" {
		_ = sp.audit(r.Context(), "saml", "slo_response", "saml", map[string]any{"init": "idp"})
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// parseLogoutRequestNameID — NameID из LogoutRequest (redirect: base64+flate;
// POST: base64 сырый XML). Только то, что нужно для завершения сессий.
func parseLogoutRequestNameID(raw string, redirectBinding bool) (string, error) {
	compressed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	payload := compressed
	if redirectBinding {
		rd := flate.NewReader(bytes.NewReader(compressed))
		payload, err = io.ReadAll(rd)
		_ = rd.Close()
		if err != nil {
			return "", err
		}
	}
	var doc struct {
		NameID string `xml:"NameID"`
	}
	if err := xml.Unmarshal(payload, &doc); err != nil {
		return "", err
	}
	return strings.TrimSpace(doc.NameID), nil
}

// clearCookie — инвалидировать cookie сессии (п. 14: HttpOnly/Secure/SameSite).
func (sp *SP) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: sp.cookieSecure(r), SameSite: sp.samesite,
	})
}

// cookieSecure — Secure по схеме запроса (за TLS-прокси — по X-Forwarded-Proto).
func (sp *SP) cookieSecure(r *http.Request) bool {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto == "https"
	}
	return r.TLS != nil
}

// audit — событие аудита best effort (отказ аудита не блокирует SSO-флоу:
// п. 14.2 требует записи, но отказ входа из-за аудита = self-DoS; фиксируем
// в логе, целостность цепочки проверяется verify).
func (sp *SP) audit(ctx context.Context, actor, action, target string, details map[string]any) error {
	if sp.hooks.Audit == nil {
		return nil
	}
	if err := sp.hooks.Audit(ctx, actor, action, target, details); err != nil && sp.hooks.Log != nil {
		sp.hooks.Log("sso: аудит не записан", "action", action, "error", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// sessionProvider — мост crewjam SessionProvider → наш SessionStore (п. 11.3:
// сессии в памяти, cookie zond_session), JIT-прvisioning и аудит входа.
// ---------------------------------------------------------------------------

type sessionProvider struct{ sp *SP }

var _ samlsp.SessionProvider = (*sessionProvider)(nil)

func (p *sessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	sp := p.sp
	subject := assertion.Subject.NameID.Value
	role := mapRole(assertion, sp.cfg.RoleAttribute)
	display := assertion.Subject.NameID.Value
	for _, stmt := range assertion.AttributeStatements {
		for _, a := range stmt.Attributes {
			if strings.EqualFold(a.Name, "displayName") || strings.EqualFold(a.FriendlyName, "displayName") ||
				strings.EqualFold(a.Name, "cn") || strings.EqualFold(a.Name, "email") {
				if len(a.Values) > 0 && a.Values[0].Value != "" {
					display = a.Values[0].Value
					goto found
				}
			}
		}
	}
found:
	if sp.hooks.UpsertUser != nil {
		if err := sp.hooks.UpsertUser(r.Context(), UserRec{
			Subject: subject, DisplayName: display, Role: role,
		}); err != nil && sp.hooks.Log != nil {
			sp.hooks.Log("sso: JIT upsert не выполнен", "subject", subject, "error", err)
		}
	}
	_ = sp.audit(r.Context(), "sso:"+subject, "sso_login_success", "sso:"+subject, map[string]any{
		"role": string(role),
	})
	sess := sp.sess.Create(subject, role)
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: sess.ID, Path: "/", HttpOnly: true,
		Secure: sp.cookieSecure(r), SameSite: sp.samesite, Expires: sess.ExpiresAt,
	})
	return nil
}

func (p *sessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(SessionCookie); err == nil {
		p.sp.sess.Delete(c.Value)
	}
	p.sp.clearCookie(w, r)
	return nil
}

func (p *sessionProvider) GetSession(r *http.Request) (samlsp.Session, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil, samlsp.ErrNoSession
	}
	sess, ok := p.sp.sess.Get(c.Value)
	if !ok {
		return nil, samlsp.ErrNoSession
	}
	return &sess, nil
}

// mapRole — роль из assertion (п. 11.3): атрибут role_attribute (значения
// admin/viewer) и группы (groups/memberOf, токены пути "zond-admin" и т.п.);
// максимальная роль из найденных; не найдено — viewer (минимальная).
func mapRole(a *saml.Assertion, roleAttribute string) Role {
	var roles []Role
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if !strings.EqualFold(attr.Name, roleAttribute) &&
				!strings.EqualFold(attr.FriendlyName, roleAttribute) &&
				!strings.EqualFold(attr.Name, "groups") &&
				!strings.EqualFold(attr.Name, "memberOf") {
				continue
			}
			for _, v := range attr.Values {
				roles = append(roles, rolesFromValue(v.Value)...)
			}
		}
	}
	return MaxRole(roles...)
}

// rolesFromValue — токены значения (разделители путей/списков), равные
// "admin"/"viewer" (регистронезависимо), дают роль.
func rolesFromValue(v string) []Role {
	var out []Role
	for _, tok := range strings.FieldsFunc(v, func(c rune) bool {
		return c == '/' || c == ':' || c == ';' || c == ',' || c == ' ' || c == '|'
	}) {
		switch strings.ToLower(strings.TrimSpace(tok)) {
		case "admin", "admins":
			out = append(out, RoleAdmin)
		case "viewer", "viewers":
			out = append(out, RoleViewer)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Метаданные IdP: стартовая загрузка и refresh (п. 11.3: refresh 24 ч).
// ---------------------------------------------------------------------------

// FetchMetadata читает метаданные IdP (url или файл; url — с таймаутом).
func FetchMetadata(metadataURL, metadataFile string, client *http.Client) ([]byte, error) {
	if metadataFile != "" {
		b, err := os.ReadFile(metadataFile)
		if err != nil {
			return nil, fmt.Errorf("sso: чтение idp_metadata_file: %w", err)
		}
		return b, nil
	}
	if metadataURL == "" {
		return nil, errors.New("sso: не заданы idp_metadata_url/idp_metadata_file")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("sso: загрузка метаданных IdP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sso: метаданные IdP: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// RunMetadataRefresh — фоновая перезагрузка метаданных IdP каждый interval
// (п. 11.3, default 24 ч). Ошибка — warn в лог/аудит, действует прежняя
// версия middleware. Завершается с ctx.
func (sp *SP) RunMetadataRefresh(ctx context.Context, metadataURL, metadataFile string, client *http.Client, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b, err := FetchMetadata(metadataURL, metadataFile, client)
			if err != nil {
				if sp.hooks.Log != nil {
					sp.hooks.Log("sso: refresh метаданных IdP не удался (действует прежняя версия)", "error", err)
				}
				_ = sp.audit(ctx, "saml", "sso_metadata_refresh_failed", "saml", map[string]any{"level": "warn", "reason": truncateRunes(err.Error(), 160)})
				continue
			}
			m, err := sp.buildMiddleware(b)
			if err != nil {
				if sp.hooks.Log != nil {
					sp.hooks.Log("sso: разбор обновлённых метаданных IdP не удался", "error", err)
				}
				continue
			}
			sp.m.Store(m)
			_ = sp.audit(ctx, "saml", "sso_metadata_refreshed", "saml", map[string]any{"bytes": len(b)})
		}
	}
}
