// Package config — загрузка и валидация YAML-конфигов (ADR-0009).
// Три файла: connections.yaml, detectors.yaml, taxonomy.yaml.
// Секреты — только ${ENV}-интерполяция; незаданная переменная = fail-fast
// с перечнем всех недостающих (blueprint п. 12, п. 18.1: поле version).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

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
}

// Source — один источник данных.
type Source struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"` // clickhouse | mongodb | <db> по конвенции путей
	DSN  string `yaml:"dsn"`  // либо DSN, либо URI — ровно один источник адреса
	URI  string `yaml:"uri"`
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
		if (s.DSN == "") == (s.URI == "") {
			errs = append(errs, fmt.Errorf("sources[%d] (%s): ровно одно из полей dsn/uri обязательно", i, s.Name))
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
	return errors.Join(errs...)
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
