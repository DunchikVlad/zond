package config

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DetectorsView — редактируемые через UI скалярные настройки detectors.yaml
// (S8-8, ADR-0014: горячая перезагрузка порогов/весов/лимитов). Реестр
// агентов через UI не правится (endpoint/egress — рестарт, см. security note).
type DetectorsView struct {
	Profile          string // quick | deep | custom
	TauAccept        float64
	TauReview        float64
	WMeta            float64
	WRules           float64
	WLLM             float64
	Similarity       float64
	MaxSize          int
	MaxConcurrent    int
	RateLimitRPS     float64
	CostScanLimitUSD float64
	Offline          bool
}

// DetectorsEditor — правка detectors.yaml через yaml.v3 Node (комментарии
// сохраняются; секретов в файле нет — только имена env, поэтому round-trip
// безопасен, но Node-правка консистентна с SourceEditor).
type DetectorsEditor struct {
	root *yaml.Node
	path string
}

// OpenDetectorsEditor читает и разбирает detectors.yaml.
func OpenDetectorsEditor(path string) (*DetectorsEditor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("detectors editor: чтение %s: %w", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("detectors editor: парсинг %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("detectors editor: %s — не mapping в корне", path)
	}
	return &DetectorsEditor{root: &root, path: path}, nil
}

// View — текущие значения редактируемых полей.
func (e *DetectorsEditor) View() (DetectorsView, error) {
	root := e.root.Content[0]
	getF := func(section, key string) float64 {
		v, _ := strconv.ParseFloat(mappingGet(mappingFind(root, section), key), 64)
		return v
	}
	getI := func(section, key string) int {
		v, _ := strconv.Atoi(mappingGet(mappingFind(root, section), key))
		return v
	}
	getB := func(section, key string) bool {
		return mappingGet(mappingFind(root, section), key) == "true"
	}
	weights := mappingFindPath(root, "ensemble", "weights")
	getW := func(key string) float64 {
		v, _ := strconv.ParseFloat(mappingGet(weights, key), 64)
		return v
	}
	return DetectorsView{
		Profile:          mappingGet(mappingFind(root, "scan"), "profile"),
		TauAccept:        getF("ensemble", "tau_accept"),
		TauReview:        getF("ensemble", "tau_review"),
		WMeta:            getW("meta"),
		WRules:           getW("rules"),
		WLLM:             getW("llm"),
		Similarity:       getF("cluster", "similarity"),
		MaxSize:          getI("cluster", "max_size"),
		MaxConcurrent:    getI("proxy", "max_concurrent"),
		RateLimitRPS:     getF("proxy", "rate_limit_rps"),
		CostScanLimitUSD: getF("proxy", "cost_scan_limit_usd"),
		Offline:          getB("proxy", "offline"),
	}, nil
}

// Apply — запись значений в дерево с fail-fast валидацией.
func (e *DetectorsEditor) Apply(v DetectorsView) error {
	if !slices.Contains(scanProfiles, v.Profile) {
		return fmt.Errorf("detectors: profile %q — допустимы %v", v.Profile, scanProfiles)
	}
	root := e.root.Content[0]
	set := func(section, key, val string) {
		sec := mappingEnsure(root, section)
		mappingSetAuto(sec, key, val)
	}
	set("scan", "profile", v.Profile)
	set("ensemble", "tau_accept", strconv.FormatFloat(v.TauAccept, 'f', -1, 64))
	set("ensemble", "tau_review", strconv.FormatFloat(v.TauReview, 'f', -1, 64))
	ens := mappingEnsure(root, "ensemble")
	weights := mappingEnsure(ens, "weights")
	mappingSetAuto(weights, "meta", strconv.FormatFloat(v.WMeta, 'f', -1, 64))
	mappingSetAuto(weights, "rules", strconv.FormatFloat(v.WRules, 'f', -1, 64))
	mappingSetAuto(weights, "llm", strconv.FormatFloat(v.WLLM, 'f', -1, 64))
	set("cluster", "similarity", strconv.FormatFloat(v.Similarity, 'f', -1, 64))
	set("cluster", "max_size", strconv.Itoa(v.MaxSize))
	set("proxy", "max_concurrent", strconv.Itoa(v.MaxConcurrent))
	set("proxy", "rate_limit_rps", strconv.FormatFloat(v.RateLimitRPS, 'f', -1, 64))
	set("proxy", "cost_scan_limit_usd", strconv.FormatFloat(v.CostScanLimitUSD, 'f', -1, 64))
	set("proxy", "offline", strconv.FormatBool(v.Offline))
	raw, err := e.Bytes()
	if err != nil {
		return err
	}
	var d Detectors
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("detectors editor: схема: %w", err)
	}
	return d.Validate()
}

// Bytes сериализует дерево (комментарии сохранены).
func (e *DetectorsEditor) Bytes() ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(e.root); err != nil {
		return nil, fmt.Errorf("detectors editor: сериализация: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// Path — путь редактируемого файла.
func (e *DetectorsEditor) Path() string { return e.path }

// mappingFind — дочерний mapping секции (nil, если нет).
func mappingFind(root *yaml.Node, section string) *yaml.Node {
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == section {
			if root.Content[i+1].Kind == yaml.MappingNode {
				return root.Content[i+1]
			}
			return nil
		}
	}
	return nil
}

// mappingFindPath — вложенный mapping по цепочке секций (nil, если нет).
func mappingFindPath(root *yaml.Node, path ...string) *yaml.Node {
	cur := root
	for _, p := range path {
		cur = mappingFind(cur, p)
		if cur == nil {
			return nil
		}
	}
	return cur
}

// scalarAuto — скаляр с типизацией по содержимому (числа/бул без тега str).
func scalarAuto(v string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: v}
	if _, err := strconv.ParseFloat(v, 64); err == nil || v == "true" || v == "false" {
		return n // без тега — yaml типизирует при чтении
	}
	n.Tag = "!!str"
	return n
}

// mappingSetAuto — upsert ключа со scalarAuto (числа не превращаются в str).
func mappingSetAuto(n *yaml.Node, key, val string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = scalarAuto(val)
			return
		}
	}
	n.Content = append(n.Content, scalar(key), scalarAuto(val))
}

// mappingEnsure — дочерний mapping секции, создаёт при отсутствии.
func mappingEnsure(root *yaml.Node, section string) *yaml.Node {
	if n := mappingFind(root, section); n != nil {
		return n
	}
	sec := &yaml.Node{Kind: yaml.MappingNode}
	root.Content = append(root.Content, scalar(section), sec)
	return sec
}
