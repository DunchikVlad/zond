package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

// SourceEntry — редактируемое представление записи источника для UI (S8-7).
// DSN/URI хранятся как в файле — с ${ENV}-литералами (п. 12).
type SourceEntry struct {
	Name                string `yaml:"name"`
	Type                string `yaml:"type"` // clickhouse | mongodb
	DSN                 string `yaml:"dsn,omitempty"`
	URI                 string `yaml:"uri,omitempty"`
	Ref                 string `yaml:"ref,omitempty"`
	Schedule            string `yaml:"schedule,omitempty"`
	ScanWindow          string `yaml:"scan_window,omitempty"`
	MaxConcurrentScans  int    `yaml:"max_concurrent_scans,omitempty"`
	MaxConcurrentTables int    `yaml:"max_concurrent_tables,omitempty"`
	QueryTimeoutS       int    `yaml:"query_timeout_s,omitempty"`
}

// SourceEditor — правка sources (включая schedule/scan_window) в raw
// connections.yaml через yaml.v3 Node: комментарии файла и ${ENV}-литералы
// сохраняются (ADR-0009: файл остаётся источником правды; UI — способ его
// править, а не альтернативное хранилище).
type SourceEditor struct {
	root *yaml.Node
	path string
}

// OpenSourceEditor читает и разбирает connections.yaml.
func OpenSourceEditor(path string) (*SourceEditor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("source editor: чтение %s: %w", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("source editor: парсинг %s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("source editor: %s — не mapping в корне", path)
	}
	return &SourceEditor{root: &root, path: path}, nil
}

var sourceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Sources — список записей источников из файла (raw-значения, без ENV-интерполяции).
func (e *SourceEditor) Sources() ([]SourceEntry, error) {
	seq, err := e.sourcesSeq()
	if err != nil {
		return nil, err
	}
	out := make([]SourceEntry, 0, len(seq.Content))
	for _, item := range seq.Content {
		var se SourceEntry
		if err := item.Decode(&se); err != nil {
			return nil, fmt.Errorf("source editor: запись источника: %w", err)
		}
		out = append(out, se)
	}
	return out, nil
}

// Upsert добавляет или обновляет запись источника (валидация fail-fast).
func (e *SourceEditor) Upsert(se SourceEntry) error {
	if err := se.Validate(); err != nil {
		return err
	}
	seq, err := e.sourcesSeq()
	if err != nil {
		return err
	}
	for _, item := range seq.Content {
		if mappingGet(item, "name") == se.Name {
			applySourceEntry(item, se)
			return nil
		}
	}
	node := &yaml.Node{Kind: yaml.MappingNode}
	applySourceEntry(node, se)
	seq.Content = append(seq.Content, node)
	return nil
}

// Delete удаляет запись по имени; отсутствие — ошибка.
func (e *SourceEditor) Delete(name string) error {
	seq, err := e.sourcesSeq()
	if err != nil {
		return err
	}
	for i, item := range seq.Content {
		if mappingGet(item, "name") == name {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("source editor: источник %q не найден", name)
}

// Bytes сериализует дерево обратно (комментарии сохранены).
func (e *SourceEditor) Bytes() ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(e.root); err != nil {
		return nil, fmt.Errorf("source editor: сериализация: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// ValidateAll — strict decode и полная Connections.Validate итогового файла
// (без ENV-интерполяции: ${VAR} — просто строки).
func (e *SourceEditor) ValidateAll() error {
	raw, err := e.Bytes()
	if err != nil {
		return err
	}
	var c Connections
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("source editor: схема файла: %w", err)
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("source editor: валидация файла: %w", err)
	}
	return nil
}

// Path — путь редактируемого файла.
func (e *SourceEditor) Path() string { return e.path }

func (e *SourceEditor) sourcesSeq() (*yaml.Node, error) {
	root := e.root.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "sources" {
			seq := root.Content[i+1]
			if seq.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("source editor: sources — не список")
			}
			return seq, nil
		}
	}
	// sources отсутствует — создаём пустую секцию (крайний случай).
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	root.Content = append(root.Content, scalar("sources"), seq)
	return seq, nil
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

func mappingGet(n *yaml.Node, key string) string {
	if n == nil || n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1].Value
		}
	}
	return ""
}

// mappingSet — upsert ключа в mapping-ноде (создаёт пару в конце).
func mappingSet(n *yaml.Node, key, val string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = scalar(val)
			return
		}
	}
	n.Content = append(n.Content, scalar(key), scalar(val))
}

// mappingDel — удаление ключа из mapping-ноды (для очистки пустых полей).
func mappingDel(n *yaml.Node, key string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}

// applySourceEntry — перезапись mapping-ноды записью (пустые поля удаляются).
func applySourceEntry(n *yaml.Node, se SourceEntry) {
	set := func(key, val string) {
		if val == "" {
			mappingDel(n, key)
			return
		}
		mappingSet(n, key, val)
	}
	setInt := func(key string, val int) {
		if val == 0 {
			mappingDel(n, key)
			return
		}
		encoded := strconv.Itoa(val)
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				n.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: encoded}
				return
			}
		}
		n.Content = append(n.Content, scalar(key), &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: encoded})
	}
	set("name", se.Name)
	set("type", se.Type)
	set("dsn", se.DSN)
	set("uri", se.URI)
	set("ref", se.Ref)
	set("schedule", se.Schedule)
	set("scan_window", se.ScanWindow)
	setInt("max_concurrent_scans", se.MaxConcurrentScans)
	setInt("max_concurrent_tables", se.MaxConcurrentTables)
	setInt("query_timeout_s", se.QueryTimeoutS)
}

// Validate — fail-fast проверка записи (ADR-0009/п. 12/п. 13.2).
func (se SourceEntry) Validate() error {
	if !sourceNameRe.MatchString(se.Name) {
		return fmt.Errorf("источник: имя %q: допустимы a-z 0-9 _ - (≤64)", se.Name)
	}
	addresses := 0
	for _, value := range []string{se.DSN, se.URI, se.Ref} {
		if value != "" {
			addresses++
		}
	}
	if addresses != 1 {
		return fmt.Errorf("источник %q: ровно одно из полей dsn/uri/ref обязательно", se.Name)
	}
	switch se.Type {
	case "clickhouse":
		if se.URI != "" {
			return fmt.Errorf("источник %q: uri неприменим к clickhouse", se.Name)
		}
		if se.DSN != "" {
			if err := checkSecretRef("dsn", se.DSN); err != nil {
				return fmt.Errorf("источник %q: %w", se.Name, err)
			}
		}
	case "mongodb":
		if se.DSN != "" {
			return fmt.Errorf("источник %q: dsn неприменим к mongodb", se.Name)
		}
		if se.URI != "" {
			if err := checkSecretRef("uri", se.URI); err != nil {
				return fmt.Errorf("источник %q: %w", se.Name, err)
			}
		}
	default:
		return fmt.Errorf("источник %q: type %q — допустимы clickhouse|mongodb", se.Name, se.Type)
	}
	for field, value := range map[string]int{
		"max_concurrent_scans": se.MaxConcurrentScans, "max_concurrent_tables": se.MaxConcurrentTables,
		"query_timeout_s": se.QueryTimeoutS,
	} {
		if value < 0 {
			return fmt.Errorf("источник %q: %s должен быть >= 0", se.Name, field)
		}
	}
	if se.Schedule != "" {
		if _, err := cron.ParseStandard(se.Schedule); err != nil {
			return fmt.Errorf("источник %q: schedule %q: невалидный cron (5 полей): %v", se.Name, se.Schedule, err)
		}
	}
	if se.ScanWindow != "" {
		if _, err := ParseWindow(se.ScanWindow); err != nil {
			return fmt.Errorf("источник %q: %w", se.Name, err)
		}
	}
	return nil
}

var envRefRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*\}$`)

// checkSecretRef — пароль в строке подключения должен быть ${ENV}-ссылкой
// (п. 12: секреты не хранятся открытым текстом; fail-closed). Парсинг
// вручную: net/url отклоняет ${...} в userinfo как invalid userinfo.
func checkSecretRef(field, conn string) error {
	if envRefRe.MatchString(conn) {
		return nil
	}
	rest := conn
	i := strings.Index(rest, "://")
	if i < 0 {
		return fmt.Errorf("%s: не URL (нет схемы://)", field)
	}
	rest = rest[i+3:]
	end := len(rest)
	if j := strings.Index(rest, "/"); j >= 0 && j < end {
		end = j
	}
	if j := strings.Index(rest, "?"); j >= 0 && j < end {
		end = j
	}
	userinfo := rest[:end]
	at := strings.LastIndex(userinfo, "@")
	if at < 0 {
		return nil // учётки нет — пароля нет
	}
	ui := userinfo[:at]
	colon := strings.Index(ui, ":")
	if colon < 0 {
		return nil // только пользователь
	}
	pass := ui[colon+1:]
	if pass != "" && !envRefRe.MatchString(pass) {
		return fmt.Errorf("%s: пароль в открытом виде запрещён (п. 12) — используйте ${ENV_NAME} вместо него", field)
	}
	return nil
}
