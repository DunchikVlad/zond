// Command zond — классификатор данных в БД (blueprint п. 1, п. 15).
// Подкоманды: version, config validate, scan (этап 1 — вертикальный срез).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
	_ "github.com/DunchikVlad/zond/internal/connector/clickhouse" // регистрация по конвенции путей
	_ "github.com/DunchikVlad/zond/internal/connector/mongodb"    // регистрация по конвенции путей
	"github.com/DunchikVlad/zond/internal/scanengine"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

// Version и Commit заполняются при сборке (Makefile, -ldflags).
var (
	Version = "dev"
	Commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Printf("zond %s (commit %s)\n", Version, Commit)
		return 0
	case "config":
		return runConfig(args[1:])
	case "scan":
		return runScan(args[1:])
	case "agent-check":
		return runAgentCheck(args[1:])
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "zond: неизвестная команда %q\n", args[0])
		usage()
		return 2
	}
}

// ---------------------------------------------------------------------------
// config validate
// ---------------------------------------------------------------------------

func runConfig(args []string) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "zond config: поддерживается только 'validate'")
		return 2
	}
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	dir := fs.String("dir", "configs", "каталог с конфигурационными файлами")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config validate: конфигурация невалидна:\n%v\n", err)
		return 2
	}
	fmt.Printf("config validate: OK (sources=%d agents=%d labels=%d taxonomy=%s)\n",
		len(b.Connections.Sources), len(b.Detectors.Agents), len(b.Taxonomy.Labels), b.Taxonomy.Version)
	return 0
}

// ---------------------------------------------------------------------------
// scan (этап 1: слои 0–1; -llm подключает слой 2, инкремент 4в)
// ---------------------------------------------------------------------------

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dir := fs.String("config", "configs", "каталог с конфигурационными файлами")
	source := fs.String("source", "", "имя источника из connections.yaml (обязательно)")
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	profile := fs.String("profile", "", "профиль quick|deep|custom (по умолчанию — из detectors.yaml)")
	useLLM := fs.Bool("llm", false, "подключить LLM-слой из реестра agents detectors.yaml")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *source == "" {
		fmt.Fprintln(os.Stderr, "scan: флаг -source обязателен")
		return 2
	}
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: конфигурация: %v\n", err)
		return 2
	}
	src, err := findSource(b.Connections, *source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		return 2
	}
	factory, ok := connector.Lookup(src.Type)
	if !ok {
		fmt.Fprintf(os.Stderr, "scan: коннектор %q не зарегистрирован (доступно: %v)\n", src.Type, connector.Types())
		return 2
	}
	dsn := src.DSN
	if dsn == "" {
		dsn = src.URI
	}
	conn, err := factory(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: подключение: %v\n", err)
		return 2
	}
	defer conn.Close()

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: verdict store: %v\n", err)
		return 2
	}
	defer st.Close()

	prof := *profile
	if prof == "" {
		prof = b.Detectors.Scan.Profile
	}
	mode := connector.SamplePercent
	if b.Detectors.Scan.Sample.Mode == "rows" {
		mode = connector.SampleRows
	}
	cfg := scanengine.Config{
		TauAccept:         b.Detectors.Ensemble.TauAccept,
		TauReview:         b.Detectors.Ensemble.TauReview,
		Weights:           b.Detectors.Ensemble.Weights,
		SampleMode:        mode,
		SampleValue:       b.Detectors.Scan.Sample.Value,
		MaxRows:           b.Detectors.Scan.Sample.MaxRows,
		MaxStringChars:    b.Detectors.Scan.Sample.MaxStringChars,
		Dedup:             b.Detectors.Scan.Sample.DedupValues,
		TaxonomyVersion:   b.Taxonomy.Version,
		DetectorsVersion:  b.Detectors.Version,
		Sensitivity:       sensitivityMap(b.Taxonomy),
		TaxonomyLabels:    taxonomyLabels(b.Taxonomy),
		Clustering:        true, // п. 7.6
		ClusterSimilarity: b.Detectors.Cluster.Similarity,
		ClusterMaxSize:    b.Detectors.Cluster.MaxSize,
		CostScanLimitUSD:  b.Detectors.Proxy.CostScanLimitUSD, // budget-стоп, п. 10.4
	}
	if len(b.Detectors.Agents) > 0 {
		// идентичность агента для ключа кэша вердиктов (п. 10.5)
		cfg.CacheScope = b.Detectors.Agents[0].ID + "|" + b.Detectors.Agents[0].Model
	}
	eng := scanengine.New(st, meta.New(b.Taxonomy.Synonyms), cfg)
	if *useLLM {
		comp, id, err := buildLLMComposite(b, taxonomyLabels(b.Taxonomy))
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan -llm:", err)
			return 2
		}
		eng.SetLLM(comp, id)
	}
	rep, err := eng.Scan(context.Background(), conn, src.Name, prof)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: %v\n", err)
		rep.Text(os.Stdout)
		return 1
	}
	rep.Text(os.Stdout)
	return 0
}

func findSource(c *config.Connections, name string) (*config.Source, error) {
	for i := range c.Sources {
		if c.Sources[i].Name == name {
			return &c.Sources[i], nil
		}
	}
	return nil, fmt.Errorf("источник %q не найден в connections.yaml", name)
}

// llmComposite — композиция прокси агентов реестра под интерфейс движка:
// Classify — прокси основного агента (agents[0]), Verify — прокси агента
// escalate_to, если задан, иначе тот же прокси (blueprint п. 7 правило 4).
type llmComposite struct {
	classify *agentproxy.Proxy
	verify   *agentproxy.Proxy
}

func (c *llmComposite) Classify(ctx context.Context, nativeType string, values []string) (*agentproxy.ClassifyResult, error) {
	return c.classify.Classify(ctx, nativeType, values)
}

func (c *llmComposite) Verify(ctx context.Context, candidate, nativeType string, values []string) (*agentproxy.VerifyResult, error) {
	return c.verify.Verify(ctx, candidate, nativeType, values)
}

// buildLLMComposite собирает LLM-слой для `zond scan -llm`: shared Gate
// лимитов (п. 10.4), прокси с egress-политикой (п. 10.7), композит эскалации.
// Любая неудача — fail-fast (код 2): скан без работающего LLM-слоя не стартует.
func buildLLMComposite(b *config.Bundle, labels []string) (scanengine.LLMClassifier, scanengine.LLMIdentity, error) {
	agents := b.Detectors.Agents
	if len(agents) == 0 {
		return nil, scanengine.LLMIdentity{}, errors.New("реестр agents пуст (detectors.yaml)")
	}
	main := agents[0]
	key := os.Getenv(main.APIKeyEnv)
	if key == "" {
		return nil, scanengine.LLMIdentity{}, fmt.Errorf("env %s не задан (api_key_env агента %s)", main.APIKeyEnv, main.ID)
	}
	gate := agentproxy.NewGate(b.Detectors.Proxy.MaxConcurrent, b.Detectors.Proxy.RateLimitRPS)
	mainProxy, err := newAgentProxy(main, key, b.Taxonomy.Version, labels, gate, b.Detectors.Proxy.Offline)
	if err != nil {
		return nil, scanengine.LLMIdentity{}, err
	}
	verifyProxy := mainProxy
	if main.EscalateTo != "" {
		var esc *config.AgentSpec
		for i := range agents {
			if agents[i].ID == main.EscalateTo {
				esc = &agents[i]
				break
			}
		}
		escKey := os.Getenv(esc.APIKeyEnv)
		if escKey == "" {
			return nil, scanengine.LLMIdentity{}, fmt.Errorf("env %s не задан (api_key_env агента-верификатора %s)", esc.APIKeyEnv, esc.ID)
		}
		verifyProxy, err = newAgentProxy(*esc, escKey, b.Taxonomy.Version, labels, gate, b.Detectors.Proxy.Offline)
		if err != nil {
			return nil, scanengine.LLMIdentity{}, err
		}
	}
	return &llmComposite{classify: mainProxy, verify: verifyProxy},
		scanengine.LLMIdentity{AgentID: main.ID, Model: main.Model}, nil
}

// newAgentProxy строит прокси агента с лимитами и egress-политикой (п. 10.4,
// п. 10.7). Ошибка конструирования (в т.ч. запрет egress) — причина fail-fast.
func newAgentProxy(a config.AgentSpec, apiKey, taxVersion string, labels []string, gate *agentproxy.Gate, offline bool) (*agentproxy.Proxy, error) {
	return agentproxy.New(agentproxy.Agent{
		ID: a.ID, Endpoint: a.Endpoint, Model: a.Model, APIKey: apiKey,
		MaxValuesPerCall: a.MaxValuesPerCall, Timeout: time.Duration(a.TimeoutS) * time.Second,
		MaxRetries: a.MaxRetries,
	}, labels, taxVersion,
		agentproxy.WithGate(gate),
		agentproxy.WithPolicy(agentproxy.Policy{Offline: offline, Allowlist: a.Allowlist}),
	)
}

func sensitivityMap(t *config.Taxonomy) map[verdict.Label]verdict.Sensitivity {
	out := make(map[verdict.Label]verdict.Sensitivity, len(t.Labels))
	for _, l := range t.Labels {
		out[verdict.Label(l.Name)] = verdict.Sensitivity(l.Sensitivity)
	}
	return out
}

// taxonomyLabels — имена лейблов для enum промпта LLM (п. 5.3).
func taxonomyLabels(t *config.Taxonomy) []string {
	out := make([]string, 0, len(t.Labels))
	for _, l := range t.Labels {
		out = append(out, l.Name)
	}
	return out
}

// ---------------------------------------------------------------------------
// agent-check (этап 4: preflight LLM-агентов, blueprint п. 15.3, п. 5.3)
// ---------------------------------------------------------------------------

func runAgentCheck(args []string) int {
	fs := flag.NewFlagSet("agent-check", flag.ContinueOnError)
	dir := fs.String("config", "configs", "каталог с конфигурационными файлами")
	online := fs.Bool("online", false, "выполнить пробный вызов к эндпоинту (иначе только конфиг+env)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-check: конфигурация: %v\n", err)
		return 2
	}
	labels := taxonomyLabels(b.Taxonomy)
	failed := 0
	for _, a := range b.Detectors.Agents {
		key := os.Getenv(a.APIKeyEnv)
		if key == "" {
			fmt.Printf("agent %s: FAIL (env %s не задан)\n", a.ID, a.APIKeyEnv)
			failed++
			continue
		}
		// Preflight п. 15.3 включает egress-политику (п. 10.7): прокси
		// строится и в offline-режиме — запрещённый эндпоинт = FAIL.
		proxy, err := agentproxy.New(agentproxy.Agent{
			ID: a.ID, Endpoint: a.Endpoint, Model: a.Model, APIKey: key,
			MaxValuesPerCall: a.MaxValuesPerCall, Timeout: time.Duration(a.TimeoutS) * time.Second,
			MaxRetries: a.MaxRetries,
		}, labels, b.Taxonomy.Version,
			agentproxy.WithPolicy(agentproxy.Policy{Offline: b.Detectors.Proxy.Offline, Allowlist: a.Allowlist}),
		)
		if err != nil {
			fmt.Printf("agent %s: FAIL (%v)\n", a.ID, err)
			failed++
			continue
		}
		if !*online {
			fmt.Printf("agent %s: OK (endpoint=%s model=%s env %s задан; пробный вызов пропущен, -online)\n",
				a.ID, a.Endpoint, a.Model, a.APIKeyEnv)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.TimeoutS)*time.Second)
		_, err = proxy.Classify(ctx, "String", []string{"ivan@example.com", "petr@test.io"})
		cancel()
		if err != nil {
			fmt.Printf("agent %s: FAIL (вызов: %v)\n", a.ID, err)
			failed++
			continue
		}
		fmt.Printf("agent %s: OK (пробный вызов успешен, model=%s)\n", a.ID, a.Model)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "agent-check: %d агент(ов) не прошли проверку\n", failed)
		return 1
	}
	fmt.Printf("agent-check: все агенты проверены (%d)\n", len(b.Detectors.Agents))
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "использование:")
	fmt.Fprintln(os.Stderr, "  zond version")
	fmt.Fprintln(os.Stderr, "  zond config validate [-dir configs]")
	fmt.Fprintln(os.Stderr, "  zond scan -source <имя> [-config configs] [-db zond.db] [-profile quick|deep|custom] [-llm]")
	fmt.Fprintln(os.Stderr, "  zond agent-check [-config configs] [-online]")
}
