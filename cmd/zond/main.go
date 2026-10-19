// Command zond — классификатор данных в БД (blueprint п. 1, п. 15).
// Подкоманды: version, config validate, scan (этап 1 — вертикальный срез).
package main

import (
	"context"
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
// scan (этап 1: слои 0–1, без LLM)
// ---------------------------------------------------------------------------

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	dir := fs.String("config", "configs", "каталог с конфигурационными файлами")
	source := fs.String("source", "", "имя источника из connections.yaml (обязательно)")
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	profile := fs.String("profile", "", "профиль quick|deep|custom (по умолчанию — из detectors.yaml)")
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
	}
	if len(b.Detectors.Agents) > 0 {
		// идентичность агента для ключа кэша вердиктов (п. 10.5)
		cfg.CacheScope = b.Detectors.Agents[0].ID + "|" + b.Detectors.Agents[0].Model
	}
	eng := scanengine.New(st, meta.New(b.Taxonomy.Synonyms), cfg)
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
		if !*online {
			fmt.Printf("agent %s: OK (endpoint=%s model=%s env %s задан; пробный вызов пропущен, -online)\n",
				a.ID, a.Endpoint, a.Model, a.APIKeyEnv)
			continue
		}
		proxy := agentproxy.New(agentproxy.Agent{
			ID: a.ID, Endpoint: a.Endpoint, Model: a.Model, APIKey: key,
			MaxValuesPerCall: a.MaxValuesPerCall, Timeout: time.Duration(a.TimeoutS) * time.Second,
			MaxRetries: a.MaxRetries,
		}, labels, b.Taxonomy.Version)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.TimeoutS)*time.Second)
		_, err := proxy.Classify(ctx, "String", []string{"ivan@example.com", "petr@test.io"})
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
	fmt.Fprintln(os.Stderr, "  zond scan -source <имя> [-config configs] [-db zond.db] [-profile quick|deep|custom]")
	fmt.Fprintln(os.Stderr, "  zond agent-check [-config configs] [-online]")
}
