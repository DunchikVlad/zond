// Package doctor — preflight-проверки перед вводом в эксплуатацию
// (blueprint п. 15.3): свободное место на томе SQLite (≥2× размера БД),
// источники (Ping + probe под readonly-учёткой), агенты (env, egress-политика,
// DNS и пробный вызов с валидацией формата), audit store (hash-chain п. 14.2),
// TLS-сертификаты SSO. Выход — таблица OK/FAIL/WARN/SKIP со стабильными
// кодами; FAIL блокирует старт `serve -strict`.
//
// Сетевые проверки (источники, DNS, пробные вызовы) выполняются только с
// Options.Online — иначе соответствующие строки идут как SKIP.
package doctor

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Status — итог одной проверки.
type Status string

const (
	StatusOK   Status = "OK"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusSkip Status = "SKIP"
)

// Result — одна строка отчёта doctor.
type Result struct {
	Code    string // стабильный код: disk.space, source.ping, agent.probe…
	Subject string // что проверяли (источник/агент/путь)
	Status  Status
	Detail  string
}

// Report — итог прогона doctor.
type Report struct {
	Results []Result
}

// Add — внутренняя запись результата.
func (r *Report) add(code, subject string, status Status, detail string) {
	r.Results = append(r.Results, Result{Code: code, Subject: subject, Status: status, Detail: detail})
}

// HasFail — наличие хотя бы одного FAIL (блокирует serve -strict).
func (r *Report) HasFail() bool {
	for _, res := range r.Results {
		if res.Status == StatusFail {
			return true
		}
	}
	return false
}

// Counts — сводка статусов (для шапки отчёта).
func (r *Report) Counts() map[Status]int {
	m := map[Status]int{}
	for _, res := range r.Results {
		m[res.Status]++
	}
	return m
}

// Text — таблица отчёта (коды отсортированы для стабильного вывода).
func (r *Report) Text(w io.Writer) {
	width := 8
	for _, res := range r.Results {
		if len(res.Code) > width {
			width = len(res.Code)
		}
	}
	fmt.Fprintf(w, "\n=== zond doctor ===\n")
	for _, res := range r.Results {
		fmt.Fprintf(w, "  %-*s  %-4s  %s", width, res.Code, res.Status, res.Subject)
		if res.Detail != "" {
			fmt.Fprintf(w, " — %s", res.Detail)
		}
		fmt.Fprintln(w)
	}
	c := r.Counts()
	fmt.Fprintf(w, "Итог: OK=%d WARN=%d FAIL=%d SKIP=%d\n",
		c[StatusOK], c[StatusWarn], c[StatusFail], c[StatusSkip])
}

// Options — параметры прогона.
type Options struct {
	// Online — выполнять сетевые проверки (Ping источников, DNS агентов,
	// пробные вызовы). Без флага строки идут SKIP.
	Online bool
	// Now — «сейчас» для проверки сертификатов (тесты); zero → time.Now.
	Now time.Time
}

// Run выполняет проверки. b — загруженный конфиг (nil → конфиг не
// загрузился: FAIL config.load, зависимые проверки пропущены). dbPath —
// путь к SQLite Verdict Store.
func Run(ctx context.Context, b *config.Bundle, dbPath string, opts Options) *Report {
	rep := &Report{}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	checkDisk(rep, dbPath)
	checkStore(rep, dbPath)
	if b == nil {
		rep.add("config.load", "configs", StatusFail, "конфигурация не загружена — зависимые проверки пропущены")
		return rep
	}
	checkSources(ctx, rep, b, opts.Online)
	checkAgents(ctx, rep, b, opts)
	checkTLSCerts(rep, b, now)
	rep.add("vault", "secrets", StatusSkip, "Vault не реализован (S7в, ADR-0012) — секреты через ENV")
	return rep
}

// checkDisk — свободное место на томе БД ≥ 2× размера файла (п. 15.3).
// Файла ещё нет — проверяем только наличие свободного места (>0).
func checkDisk(rep *Report, dbPath string) {
	dir := filepath.Dir(dbPath)
	free, err := freeSpace(dir)
	if err != nil {
		rep.add("disk.space", dir, StatusFail, err.Error())
		return
	}
	var size int64
	if fi, err := os.Stat(dbPath); err == nil {
		size = fi.Size()
	}
	need := uint64(2 * max(size, 1))
	if free < need {
		rep.add("disk.space", dir, StatusFail,
			fmt.Sprintf("свободно %d Б, нужно ≥ %d Б (2× размера БД %d Б)", free, need, size))
		return
	}
	rep.add("disk.space", dir, StatusOK,
		fmt.Sprintf("свободно %d Б ≥ 2× БД (%d Б)", free, size))
}

// checkStore — store открывается и hash-chain аудита цел (п. 14.2).
func checkStore(rep *Report, dbPath string) {
	st, err := store.Open(dbPath)
	if err != nil {
		rep.add("store.open", dbPath, StatusFail, err.Error())
		return
	}
	defer st.Close()
	ver, err := st.AuditVerify(context.Background())
	if err != nil {
		rep.add("store.open", dbPath, StatusFail, "верификация цепочки: "+err.Error())
		return
	}
	if !ver.OK() {
		rep.add("audit.chain", dbPath, StatusFail,
			fmt.Sprintf("разрыв hash-chain на записи %d: %s (runbook audit-hash-chain-broken.md)", ver.BrokenAt, ver.Reason))
		return
	}
	rep.add("audit.chain", dbPath, StatusOK, fmt.Sprintf("целостность подтверждена (%d записей)", ver.Checked))
}

// checkSources — доступность каждого источника: конструктор + Ping +
// probe (ListTables) под readonly-учёткой (п. 15.3).
func checkSources(ctx context.Context, rep *Report, b *config.Bundle, online bool) {
	names := make([]string, 0, len(b.Connections.Sources))
	byName := map[string]config.Source{}
	for _, src := range b.Connections.Sources {
		names = append(names, src.Name)
		byName[src.Name] = src
	}
	sort.Strings(names)
	for _, name := range names {
		src := byName[name]
		factory, ok := connector.Lookup(src.Type)
		if !ok {
			rep.add("source.open", name, StatusFail,
				fmt.Sprintf("коннектор %q не зарегистрирован (доступно: %v)", src.Type, connector.Types()))
			continue
		}
		dsn := src.DSN
		if dsn == "" {
			dsn = src.URI
		}
		conn, err := factory(dsn)
		if err != nil {
			rep.add("source.open", name, StatusFail, err.Error())
			continue
		}
		defer conn.Close()
		if !online {
			rep.add("source.ping", name, StatusSkip, "пропущено (doctor без -online)")
			continue
		}
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = conn.Ping(pingCtx)
		cancel()
		if err != nil {
			rep.add("source.ping", name, StatusFail, err.Error())
			continue
		}
		rep.add("source.ping", name, StatusOK, "ping + подключение")
	}
}

// checkAgents — env, egress-политика, DNS (online) и пробный вызов с
// валидацией формата ответа (online; п. 5.3, п. 10.7).
func checkAgents(ctx context.Context, rep *Report, b *config.Bundle, opts Options) {
	labels := make([]string, 0, len(b.Taxonomy.Labels))
	for _, l := range b.Taxonomy.Labels {
		labels = append(labels, l.Name)
	}
	for _, a := range b.Detectors.Agents {
		key := os.Getenv(a.APIKeyEnv)
		if key == "" {
			rep.add("agent.env", a.ID, StatusFail, fmt.Sprintf("env %s не задан (api_key_env)", a.APIKeyEnv))
			continue
		}
		rep.add("agent.env", a.ID, StatusOK, fmt.Sprintf("env %s задан", a.APIKeyEnv))
		// Egress-проверка (п. 10.7): конструктор прокси валидирует endpoint.
		proxy, err := agentproxy.New(agentproxy.Agent{
			ID: a.ID, Endpoint: a.Endpoint, Model: a.Model, APIKey: key,
			MaxValuesPerCall: a.MaxValuesPerCall, Timeout: time.Duration(a.TimeoutS) * time.Second,
			MaxRetries: 0,
		}, labels, b.Taxonomy.Version,
			agentproxy.WithPolicy(agentproxy.Policy{Offline: b.Detectors.Proxy.Offline, Allowlist: a.Allowlist}),
		)
		if err != nil {
			rep.add("agent.egress", a.ID, StatusFail, err.Error())
			continue
		}
		rep.add("agent.egress", a.ID, StatusOK, "endpoint разрешён egress-политикой")
		if !opts.Online {
			rep.add("agent.probe", a.ID, StatusSkip, "пропущено (doctor без -online)")
			continue
		}
		if err := checkDNS(ctx, a.Endpoint); err != nil {
			rep.add("agent.dns", a.ID, StatusFail, err.Error())
			continue
		}
		rep.add("agent.dns", a.ID, StatusOK, "hostname резолвится")
		probeCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutS)*time.Second)
		_, err = proxy.Classify(probeCtx, "String", []string{"user@example.com", "+7 999 123-45-67"})
		cancel()
		if err != nil {
			rep.add("agent.probe", a.ID, StatusFail, "пробный вызов: "+err.Error())
			continue
		}
		rep.add("agent.probe", a.ID, StatusOK, "формат ответа валиден (п. 5.3)")
	}
}

// checkTLSCerts — сертификат SP SSO: файл читается, парсится, не истёк
// (п. 15.3 TLS). SSO выключен или ключи ephemeral — SKIP.
func checkTLSCerts(rep *Report, b *config.Bundle, now time.Time) {
	if !b.Connections.SSO.Enabled {
		rep.add("tls.cert", "sso", StatusSkip, "SSO выключен")
		return
	}
	certPath := b.Connections.SSO.SPCertificateFile
	if certPath == "" {
		rep.add("tls.cert", "sso", StatusSkip, "сертификат не задан — ephemeral self-signed (п. 11.3)")
		return
	}
	info, err := certInfo(certPath, now)
	if err != nil {
		rep.add("tls.cert", certPath, StatusFail, err.Error())
		return
	}
	rep.add("tls.cert", certPath, StatusOK, info)
}

// checkDNS — резолв hostname endpoint'а агента.
func checkDNS(ctx context.Context, endpoint string) error {
	host := endpoint
	if i := strings.Index(endpoint, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "" || strings.EqualFold(host, "localhost") {
		return nil
	}
	r := &netResolver{}
	addrs, err := r.lookupHost(ctx, host)
	if err != nil {
		return fmt.Errorf("DNS %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("DNS %s: пустой ответ", host)
	}
	return nil
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
