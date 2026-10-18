// Command zond — классификатор данных в БД (blueprint п. 1, п. 15).
// Подкоманды: version, config validate, scan (этап 1 — вертикальный срез).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
	_ "github.com/DunchikVlad/zond/internal/connector/clickhouse" // регистрация по конвенции путей
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
		TauAccept:        b.Detectors.Ensemble.TauAccept,
		SampleMode:       mode,
		SampleValue:      b.Detectors.Scan.Sample.Value,
		MaxRows:          b.Detectors.Scan.Sample.MaxRows,
		MaxStringChars:   b.Detectors.Scan.Sample.MaxStringChars,
		Dedup:            b.Detectors.Scan.Sample.DedupValues,
		TaxonomyVersion:  b.Taxonomy.Version,
		DetectorsVersion: b.Detectors.Version,
		Sensitivity:      sensitivityMap(b.Taxonomy),
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

func usage() {
	fmt.Fprintln(os.Stderr, "использование:")
	fmt.Fprintln(os.Stderr, "  zond version")
	fmt.Fprintln(os.Stderr, "  zond config validate [-dir configs]")
	fmt.Fprintln(os.Stderr, "  zond scan -source <имя> [-config configs] [-db zond.db] [-profile quick|deep|custom]")
}
