// Package config — загрузка и валидация YAML-конфигов (ADR-0009).
// Три файла: connections.yaml, detectors.yaml, taxonomy.yaml.
// Секреты — только ${ENV}-интерполяция; незаданная переменная = fail-fast
// с перечнем всех недостающих (blueprint п. 12, п. 18.1: поле version).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Bundle — три конфигурационных файла одной инсталляции.
type Bundle struct {
	Connections *Connections
	Detectors   *Detectors
	Taxonomy    *Taxonomy
}

// LoadAll загружает и валидирует все три конфига из каталога dir.
func LoadAll(dir string) (*Bundle, error) {
	c, errC := LoadConnections(filepath.Join(dir, "connections.yaml"))
	d, errD := LoadDetectors(filepath.Join(dir, "detectors.yaml"))
	t, errT := LoadTaxonomy(filepath.Join(dir, "taxonomy.yaml"))
	if err := errors.Join(errC, errD, errT); err != nil {
		return nil, err
	}
	return &Bundle{Connections: c, Detectors: d, Taxonomy: t}, nil
}

// loadParsed читает файл, парсит строго по схеме и интерполирует ${VAR}
// в строковых полях уже распарсенной структуры (комментарии YAML не трогаем).
// Незаданная переменная = ошибка с полным перечнем (fail-fast, blueprint п. 12).
func loadParsed(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", path, err)
	}
	if err := decodeStrict(path, raw, out); err != nil {
		return err
	}
	var missing []string
	seen := map[string]bool{}
	expandEnvInValue(reflect.ValueOf(out), func(name string) string {
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		if !seen[name] {
			seen[name] = true
			missing = append(missing, name)
		}
		return ""
	})
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%s: не заданы переменные окружения: %s", path, strings.Join(missing, ", "))
	}
	return nil
}

// expandEnvInValue рекурсивно заменяет ${VAR} в строковых полях структуры.
// Вложенные структуры внутри map не разворачиваются — в конфигах их нет.
func expandEnvInValue(v reflect.Value, mapping func(string) string) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			expandEnvInValue(v.Elem(), mapping)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			expandEnvInValue(v.Field(i), mapping)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			expandEnvInValue(v.Index(i), mapping)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			mv := v.MapIndex(k)
			if mv.Kind() == reflect.String && strings.Contains(mv.String(), "$") {
				v.SetMapIndex(k, reflect.ValueOf(os.Expand(mv.String(), mapping)))
			}
		}
	case reflect.String:
		if v.CanSet() && strings.Contains(v.String(), "$") {
			v.SetString(os.Expand(v.String(), mapping))
		}
	}
}

// decodeStrict парсит YAML строго по схеме: неизвестные ключи = ошибка (ADR-0009).
func decodeStrict(path string, data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("парсинг %s: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// connections.yaml (blueprint п. 12)
// ---------------------------------------------------------------------------

// Connections — профили подключений к БД-источникам. Секретов в файле нет.
type Connections struct {
	Version string   `yaml:"version"`
	Sources []Source `yaml:"sources"`
	SSO     SSO      `yaml:"sso"`
	// Backup — расписание резервного копирования Verdict Store (п. 15.2):
	// cron-выражение и каталог копий вне инстанса. Пусто — только ручной
	// `zond backup`. Валидация выражения — задача шедулера (прецедент
	// source.schedule: warn-лог + аудит, старт не падает).
	Backup Backup `yaml:"backup"`
	// Vault — секреты подключений из HashiCorp Vault (ADR-0012, п. 12.1).
	// Выключен или блок отсутствует — прежний режим ${ENV}.
	Vault Vault `yaml:"vault"`
}

// Vault — опциональный блок secrets.Resolver (ADR-0012): address, способ
// аутентификации и записи secrets (ref → path). Секретов в файле нет:
// токен — в env (token_env) или JWT сервис-аккаунта (kubernetes).
type Vault struct {
	Enabled bool          `yaml:"enabled"`
	Address string        `yaml:"address"`
	Auth    VaultAuth     `yaml:"auth"`
	Secrets []VaultSecret `yaml:"secrets"`
}

// VaultAuth — аутентификация в Vault: method token (токен из env, dev/демо)
// или kubernetes (JWT сервис-аккаунта + роль, prod). Токен в конфиге
// запрещён (п. 12.1) — строгий парсинг отвергнет лишний ключ.
type VaultAuth struct {
	Method   string `yaml:"method"`    // token | kubernetes
	TokenEnv string `yaml:"token_env"` // method=token: имя env-переменной с токеном
	Role     string `yaml:"role"`      // method=kubernetes: роль Vault
	JWTFile  string `yaml:"jwt_file"`  // method=kubernetes: путь к JWT (по умолчанию стандартный путь SA)
}

// VaultSecret — запись vault.secrets: ref совпадает с name источника.
// Ровно один режим чтения: key (kv-v2, значение ключа — готовый DSN/URI)
// или dsn_template (dynamic database/creds, подстановка {{username}}/
// {{password}} в шаблон DSN).
type VaultSecret struct {
	Ref         string `yaml:"ref"`
	Path        string `yaml:"path"`
	Key         string `yaml:"key"`
	DSNTemplate string `yaml:"dsn_template"`
}

// Backup — расписание и каталог онлайн-копий (п. 15.2; VACUUM INTO).
type Backup struct {
	Schedule string `yaml:"schedule"` // cron; "" — без автокопий
	Dir      string `yaml:"dir"`      // каталог назначения (обязателен при schedule)
}

// Дефолты resource governance источника (blueprint п. 13.2).
const (
	DefaultMaxConcurrentScans  = 1   // max_concurrent_scans
	DefaultMaxConcurrentTables = 2   // max_concurrent_tables
	DefaultQueryTimeoutS       = 300 // таймаут запроса к БД, сек (5 мин)
)

// Source — один источник данных.
type Source struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // clickhouse | mongodb | <db> по конвенции путей
	DSN  string `yaml:"dsn"`  // DSN | URI | ref (Vault) — ровно один источник адреса
	URI  string `yaml:"uri"`
	// Ref — имя записи vault.secrets (ADR-0012): секрет читается резолвером
	// в момент установки коннекта, в конфиге секрета нет (п. 12.1).
	Ref string `yaml:"ref"`
	// Schedule — cron-выражение периодического перескана (blueprint п. 15:
	// расписание в конфиге источника). Пусто — только ручной запуск.
	// Валидация выражения — задача шедулера (при ошибке: warn-лог + аудит,
	// источник пропускается, старт serve не роняется).
	Schedule string `yaml:"schedule"`

	// Лимиты на источник (blueprint п. 13.2, resource governance):
	// 0 → дефолт спецификации. max_concurrent_scans — активные прогоны
	// источника (serve), max_concurrent_tables — таблиц в обработке
	// одновременно внутри прогона, query_timeout_s — таймаут запроса к БД
	// (сек, дефолт 300 = 5 мин).
	MaxConcurrentScans  int `yaml:"max_concurrent_scans"`
	MaxConcurrentTables int `yaml:"max_concurrent_tables"`
	QueryTimeoutS       int `yaml:"query_timeout_s"`

	// ScanWindow — окно сканирования (п. 13.2, опция): "HH:MM-HH:MM"
	// локального времени; старт перескана вне окна откладывается
	// шедулером до начала окна. Пусто — без окна (перескан по schedule
	// в любое время). Формат проверяется при загрузке (fail-fast).
	ScanWindow string `yaml:"scan_window"`
}

// ScansLimit — max_concurrent_scans с дефолтом спецификации (п. 13.2).
func (s *Source) ScansLimit() int {
	if s.MaxConcurrentScans <= 0 {
		return DefaultMaxConcurrentScans
	}
	return s.MaxConcurrentScans
}

// TablesLimit — max_concurrent_tables с дефолтом спецификации (п. 13.2).
func (s *Source) TablesLimit() int {
	if s.MaxConcurrentTables <= 0 {
		return DefaultMaxConcurrentTables
	}
	return s.MaxConcurrentTables
}

// QueryTimeout — таймаут запроса к БД с дефолтом спецификации (п. 13.2).
func (s *Source) QueryTimeout() time.Duration {
	if s.QueryTimeoutS <= 0 {
		return DefaultQueryTimeoutS * time.Second
	}
	return time.Duration(s.QueryTimeoutS) * time.Second
}

// SSO — параметры SAML 2.0 Service Provider (ADR-0011). Только публичные поля.
type SSO struct {
	Enabled            bool   `yaml:"enabled"`
	EntityID           string `yaml:"entity_id"`
	ACSURL             string `yaml:"acs_url"`
	IDPMetadataURL     string `yaml:"idp_metadata_url"`
	IDPMetadataFile    string `yaml:"idp_metadata_file"`
	NameIDFormat       string `yaml:"name_id_format"`
	RoleAttribute      string `yaml:"role_attribute"`
	AdminTokenFallback bool   `yaml:"admin_token_fallback"`

	// Инкремент 5в-5: ключи подписи SP (п. 11.3: сертификат из конфигурации,
	// ротация «добавить новый → раскатать → убрать старый»). Не заданы —
	// ephemeral self-signed на старте (dev/демо, предупреждение в лог/аудит).
	SPCertificateFile string `yaml:"sp_certificate_file"`
	SPKeyFile         string `yaml:"sp_key_file"`
	// CookieSameSite — lax (default, http-dev) | none (prod за TLS + Secure).
	// На http с lax часть браузеров не пошлёт tracked-request cookie на POST
	// ACS (п. 14 SameSite=Lax) — prod-развёртывание обязано использовать https.
	CookieSameSite string `yaml:"cookie_samesite"`
}

// Validate — fail-fast проверка схемы connections.yaml.
func (c *Connections) Validate() error {
	var errs []error
	if c.Version == "" {
		errs = append(errs, errors.New("connections: поле version обязательно (п. 18.1 blueprint)"))
	}
	seen := make(map[string]bool, len(c.Sources))
	for i, s := range c.Sources {
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("sources[%d]: name обязателен", i))
		} else if seen[s.Name] {
			errs = append(errs, fmt.Errorf("sources[%d]: дубль имени %q", i, s.Name))
		}
		seen[s.Name] = true
		if s.Type == "" {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): type обязателен", i, s.Name))
		}
		n := 0
		for _, addr := range []string{s.DSN, s.URI, s.Ref} {
			if addr != "" {
				n++
			}
		}
		if n != 1 {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): ровно одно из полей dsn/uri/ref обязательно", i, s.Name))
		}
		if s.Ref != "" && !c.Vault.Enabled {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): ref требует vault.enabled=true (ADR-0012)", i, s.Name))
		}
		// Лимиты п. 13.2: 0 → дефолт спецификации; отрицательные запрещены.
		if s.MaxConcurrentScans < 0 {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): max_concurrent_scans должен быть >= 0 (0 = default %d, п. 13.2)", i, s.Name, DefaultMaxConcurrentScans))
		}
		if s.MaxConcurrentTables < 0 {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): max_concurrent_tables должен быть >= 0 (0 = default %d, п. 13.2)", i, s.Name, DefaultMaxConcurrentTables))
		}
		if s.QueryTimeoutS < 0 {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): query_timeout_s должен быть >= 0 (0 = default %d, п. 13.2)", i, s.Name, DefaultQueryTimeoutS))
		}
		if s.ScanWindow != "" {
			if _, err := ParseWindow(s.ScanWindow); err != nil {
				errs = append(errs, fmt.Errorf("sources[%d] (%s): scan_window: %w", i, s.Name, err))
			}
		}
	}
	if err := c.Vault.validate(seen); err != nil {
		errs = append(errs, err)
	}
	for _, s := range c.Sources {
		if s.Ref == "" || !c.Vault.Enabled {
			continue
		}
		found := false
		for _, vs := range c.Vault.Secrets {
			if vs.Ref == s.Ref {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("sources (%s): ref %q не найден в vault.secrets", s.Name, s.Ref))
		}
	}
	if c.SSO.Enabled {
		if c.SSO.EntityID == "" || c.SSO.ACSURL == "" {
			errs = append(errs, errors.New("sso: entity_id и acs_url обязательны при enabled: true"))
		}
		if c.SSO.IDPMetadataURL == "" && c.SSO.IDPMetadataFile == "" {
			errs = append(errs, errors.New("sso: idp_metadata_url или idp_metadata_file обязателен при enabled: true"))
		}
		if c.SSO.RoleAttribute == "" {
			errs = append(errs, errors.New("sso: role_attribute обязателен при enabled: true"))
		}
		switch c.SSO.CookieSameSite {
		case "", "lax", "none":
		default:
			errs = append(errs, fmt.Errorf("sso: cookie_samesite допустимы lax|none, получено %q", c.SSO.CookieSameSite))
		}
	}
	if c.Backup.Schedule != "" && c.Backup.Dir == "" {
		errs = append(errs, errors.New("backup: dir обязателен при заданном schedule (п. 15.2)"))
	}
	return errors.Join(errs...)
}

// validate — fail-fast проверка блока vault (ADR-0012, п. 12.1).
// sourceNames — имена источников (ref записи совпадает с name источника).
func (v *Vault) validate(sourceNames map[string]bool) error {
	configured := v.Address != "" || v.Auth.Method != "" || len(v.Secrets) > 0
	if !v.Enabled {
		if configured {
			return errors.New("vault: блок настроен, но enabled=false (либо включите, либо уберите)")
		}
		return nil
	}
	var errs []error
	if v.Address == "" {
		errs = append(errs, errors.New("vault: address обязателен при enabled=true"))
	}
	switch v.Auth.Method {
	case "token":
		if v.Auth.TokenEnv == "" {
			errs = append(errs, errors.New("vault: auth.token_env обязателен при method=token (п. 12.1: токен в конфиге запрещён)"))
		}
	case "kubernetes":
		if v.Auth.Role == "" {
			errs = append(errs, errors.New("vault: auth.role обязателен при method=kubernetes"))
		}
	default:
		errs = append(errs, fmt.Errorf("vault: auth.method допустимы token|kubernetes, получено %q", v.Auth.Method))
	}
	seenRef := make(map[string]bool, len(v.Secrets))
	for i, s := range v.Secrets {
		if s.Ref == "" {
			errs = append(errs, fmt.Errorf("vault.secrets[%d]: ref обязателен (совпадает с name источника)", i))
		} else if seenRef[s.Ref] {
			errs = append(errs, fmt.Errorf("vault.secrets[%d]: дубль ref %q", i, s.Ref))
		}
		seenRef[s.Ref] = true
		if s.Path == "" {
			errs = append(errs, fmt.Errorf("vault.secrets[%d] (%s): path обязателен", i, s.Ref))
		}
		switch {
		case s.Key == "" && s.DSNTemplate == "":
			errs = append(errs, fmt.Errorf("vault.secrets[%d] (%s): одно из key (kv-v2) | dsn_template (dynamic) обязательно", i, s.Ref))
		case s.Key != "" && s.DSNTemplate != "":
			errs = append(errs, fmt.Errorf("vault.secrets[%d] (%s): key и dsn_template взаимоисключающи", i, s.Ref))
		case s.DSNTemplate != "":
			for _, ph := range []string{"{{username}}", "{{password}}"} {
				if !strings.Contains(s.DSNTemplate, ph) {
					errs = append(errs, fmt.Errorf("vault.secrets[%d] (%s): dsn_template должен содержать %s", i, s.Ref, ph))
				}
			}
		}
		if s.Ref != "" && !sourceNames[s.Ref] {
			errs = append(errs, fmt.Errorf("vault.secrets[%d] (%s): ref не совпадает ни с одним источником", i, s.Ref))
		}
	}
	return errors.Join(errs...)
}

// LoadConnections загружает connections.yaml с интерполяцией секретов из ENV.
func LoadConnections(path string) (*Connections, error) {
	var c Connections
	if err := loadParsed(path, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ---------------------------------------------------------------------------
// detectors.yaml (blueprint п. 5.2, п. 5.3, п. 7, п. 12)
// ---------------------------------------------------------------------------

// Detectors — пороги каскада, профили сэмплирования и реестр агентов.
// Hot-reload без рестарта — ADR-0014 (реализация позже, контракт — сейчас).
type Detectors struct {
	Version  string         `yaml:"version"`
	Scan     ScanConfig     `yaml:"scan"`
	Ensemble EnsembleConfig `yaml:"ensemble"`
	Agents   []AgentSpec    `yaml:"agents"`
	Cluster  ClusterConfig  `yaml:"cluster"` // п. 7.6
	Proxy    ProxyConfig    `yaml:"proxy"`   // п. 10.4, п. 10.7
}

// ProxyConfig — лимиты и budget-стоп LLM-слоя (blueprint п. 10.4) и флаг
// offline egress-политики (п. 10.7). Нули — значения по умолчанию/без лимита.
type ProxyConfig struct {
	Offline          bool    `yaml:"offline"`             // п. 10.7: запретить эндпоинты вне allowlist
	MaxConcurrent    int     `yaml:"max_concurrent"`      // семафор, 0 → default 8
	RateLimitRPS     float64 `yaml:"rate_limit_rps"`      // 0 → без лимита
	CostScanLimitUSD float64 `yaml:"cost_scan_limit_usd"` // 0 → без лимита
}

// ClusterConfig — кластеризация колонок по отпечатку (blueprint п. 7.6).
type ClusterConfig struct {
	Similarity float64 `yaml:"similarity"` // порх сходства (0,1], default 0.8
	MaxSize    int     `yaml:"max_size"`   // размер кластера, default 100
}

// ScanConfig — профиль и параметры сэмплирования (blueprint п. 5.2).
type ScanConfig struct {
	Profile string       `yaml:"profile"` // quick | deep | custom
	Sample  SampleConfig `yaml:"sample"`
}

// SampleConfig — режим N строк или p% с предохранителями.
type SampleConfig struct {
	Mode           string  `yaml:"mode"` // rows | percent
	Value          float64 `yaml:"value"`
	MinRows        int64   `yaml:"min_rows"`
	MaxRows        int64   `yaml:"max_rows"`
	MaxStringChars int     `yaml:"max_string_chars"`
	DedupValues    bool    `yaml:"dedup_values"`
}

// EnsembleConfig — пороги и веса ансамбля (blueprint п. 5.6, п. 7).
type EnsembleConfig struct {
	TauAccept float64            `yaml:"tau_accept"`
	TauReview float64            `yaml:"tau_review"`
	Weights   map[string]float64 `yaml:"weights"` // meta | rules | llm
}

// AgentSpec — запись реестра LLM-агентов (blueprint п. 5.3).
type AgentSpec struct {
	ID               string     `yaml:"id"`
	Endpoint         string     `yaml:"endpoint"`
	Model            string     `yaml:"model"`
	APIKeyEnv        string     `yaml:"api_key_env"`
	MaxValuesPerCall int        `yaml:"max_values_per_call"`
	TimeoutS         int        `yaml:"timeout_s"`
	MaxRetries       int        `yaml:"max_retries"`
	ConfidenceBand   [2]float64 `yaml:"confidence_band"`
	EscalateTo       string     `yaml:"escalate_to"`
	Allowlist        []string   `yaml:"allowlist"` // п. 10.7: IP/CIDR/hostname, иначе — только loopback/RFC 1918
}

var sampleModes = []string{"rows", "percent"}
var scanProfiles = []string{"quick", "deep", "custom"}
var ensembleLayers = []string{"meta", "rules", "llm"}

// Validate — fail-fast проверка схемы detectors.yaml.
func (d *Detectors) Validate() error {
	var errs []error
	if d.Version == "" {
		errs = append(errs, errors.New("detectors: поле version обязательно (п. 18.1 blueprint)"))
	}
	if !slices.Contains(scanProfiles, d.Scan.Profile) {
		errs = append(errs, fmt.Errorf("scan.profile: допустимы %v, получено %q", scanProfiles, d.Scan.Profile))
	}
	if !slices.Contains(sampleModes, d.Scan.Sample.Mode) {
		errs = append(errs, fmt.Errorf("scan.sample.mode: допустимы %v, получено %q", sampleModes, d.Scan.Sample.Mode))
	}
	if d.Scan.Sample.Value <= 0 {
		errs = append(errs, errors.New("scan.sample.value должен быть > 0"))
	}
	if d.Scan.Sample.MaxRows <= 0 {
		errs = append(errs, errors.New("scan.sample.max_rows должен быть > 0"))
	}
	if d.Ensemble.TauAccept <= 0 || d.Ensemble.TauAccept > 1 {
		errs = append(errs, fmt.Errorf("ensemble.tau_accept должен быть в (0, 1], получено %v", d.Ensemble.TauAccept))
	}
	if d.Ensemble.TauReview < 0 || d.Ensemble.TauReview >= 1 {
		errs = append(errs, fmt.Errorf("ensemble.tau_review должен быть в [0, 1), получено %v", d.Ensemble.TauReview))
	}
	if d.Ensemble.TauReview >= d.Ensemble.TauAccept {
		errs = append(errs, errors.New("ensemble: tau_review должен быть < tau_accept"))
	}
	for layer, w := range d.Ensemble.Weights {
		if !slices.Contains(ensembleLayers, layer) {
			errs = append(errs, fmt.Errorf("ensemble.weights: неизвестный слой %q (допустимы %v)", layer, ensembleLayers))
		}
		if w <= 0 {
			errs = append(errs, fmt.Errorf("ensemble.weights[%s]: вес должен быть > 0", layer))
		}
	}
	ids := make(map[string]bool, len(d.Agents))
	for i, a := range d.Agents {
		if a.ID == "" {
			errs = append(errs, fmt.Errorf("agents[%d]: id обязателен", i))
		} else if ids[a.ID] {
			errs = append(errs, fmt.Errorf("agents[%d]: дубль id %q", i, a.ID))
		}
		ids[a.ID] = true
		if a.Endpoint == "" {
			errs = append(errs, fmt.Errorf("agents[%d] (%s): endpoint обязателен", i, a.ID))
		}
		if a.APIKeyEnv == "" {
			errs = append(errs, fmt.Errorf("agents[%d] (%s): api_key_env обязателен (имя env-переменной, не ключ)", i, a.ID))
		}
		if a.MaxValuesPerCall <= 0 || a.TimeoutS <= 0 || a.MaxRetries < 0 {
			errs = append(errs, fmt.Errorf("agents[%d] (%s): max_values_per_call>0, timeout_s>0, max_retries>=0", i, a.ID))
		}
		band := a.ConfidenceBand
		if band[0] < 0 || band[1] > 1 || band[0] >= band[1] {
			errs = append(errs, fmt.Errorf("agents[%d] (%s): confidence_band должен быть [lo, hi] в пределах [0,1], lo<hi", i, a.ID))
		}
		for j, entry := range a.Allowlist {
			if !validAllowlistEntry(entry) {
				errs = append(errs, fmt.Errorf("agents[%d] (%s): allowlist[%d]=%q — не IP/CIDR и не hostname (п. 10.7)", i, a.ID, j, entry))
			}
		}
	}
	for i, a := range d.Agents {
		if a.EscalateTo != "" && !ids[a.EscalateTo] {
			errs = append(errs, fmt.Errorf("agents[%d] (%s): escalate_to=%q не найден в реестре", i, a.ID, a.EscalateTo))
		}
	}
	if d.Cluster.Similarity != 0 && (d.Cluster.Similarity <= 0 || d.Cluster.Similarity > 1) {
		errs = append(errs, fmt.Errorf("cluster.similarity должен быть в (0, 1], получено %v", d.Cluster.Similarity))
	}
	if d.Cluster.MaxSize < 0 {
		errs = append(errs, fmt.Errorf("cluster.max_size должен быть >= 0 (0 = default 100)"))
	}
	if d.Proxy.MaxConcurrent < 0 {
		errs = append(errs, fmt.Errorf("proxy.max_concurrent должен быть >= 0 (0 = default 8, п. 10.4)"))
	}
	if d.Proxy.RateLimitRPS < 0 {
		errs = append(errs, fmt.Errorf("proxy.rate_limit_rps должен быть >= 0 (0 = без лимита, п. 10.4)"))
	}
	if d.Proxy.CostScanLimitUSD < 0 {
		errs = append(errs, fmt.Errorf("proxy.cost_scan_limit_usd должен быть >= 0 (0 = без лимита, п. 10.4)"))
	}
	return errors.Join(errs...)
}

// validAllowlistEntry — запись allowlist валидна, если парсится как IP/CIDR
// (netip) или hostname: буквы/цифры/'.'/'-', начинается и кончается alnum
// (blueprint п. 10.7).
func validAllowlistEntry(s string) bool {
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) && s[i] != '.' && s[i] != '-' {
			return false
		}
	}
	return isAlnum(s[0]) && isAlnum(s[len(s)-1])
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// LoadDetectors загружает detectors.yaml (секретов нет — только имена env).
func LoadDetectors(path string) (*Detectors, error) {
	var d Detectors
	if err := loadParsed(path, &d); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// ---------------------------------------------------------------------------
// taxonomy.yaml (blueprint п. 5.5; ADR-0004)
// ---------------------------------------------------------------------------

// Taxonomy — версионируемый список лейблов и их чувствительности.
type Taxonomy struct {
	Version  string              `yaml:"version"`
	Labels   []LabelDef          `yaml:"labels"`
	Synonyms map[string][]string `yaml:"synonyms"` // label → токены имён колонок (словарь слоя 0)
}

// LabelDef — лейбл и класс чувствительности.
type LabelDef struct {
	Name        string `yaml:"name"`
	Sensitivity string `yaml:"sensitivity"` // PII | PCI | PHI | none
}

var sensitivities = []string{"PII", "PCI", "PHI", "none"}

// Validate — fail-fast проверка схемы taxonomy.yaml.
func (t *Taxonomy) Validate() error {
	var errs []error
	if t.Version == "" {
		errs = append(errs, errors.New("taxonomy: поле version обязательно (semver, ADR-0004)"))
	}
	seen := make(map[string]bool, len(t.Labels))
	labelOK := map[string]bool{}
	for i, l := range t.Labels {
		if l.Name == "" {
			errs = append(errs, fmt.Errorf("labels[%d]: name обязателен", i))
		} else if seen[l.Name] {
			errs = append(errs, fmt.Errorf("labels[%d]: дубль лейбла %q", i, l.Name))
		}
		seen[l.Name] = true
		labelOK[l.Name] = true
		if !slices.Contains(sensitivities, l.Sensitivity) {
			errs = append(errs, fmt.Errorf("labels[%d] (%s): sensitivity допустимы %v, получено %q", i, l.Name, sensitivities, l.Sensitivity))
		}
	}
	for label := range t.Synonyms {
		if !labelOK[label] {
			errs = append(errs, fmt.Errorf("synonyms: лейбл %q отсутствует в labels", label))
		}
	}
	return errors.Join(errs...)
}

// LoadTaxonomy загружает taxonomy.yaml.
func LoadTaxonomy(path string) (*Taxonomy, error) {
	var t Taxonomy
	if err := loadParsed(path, &t); err != nil {
		return nil, err
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}
