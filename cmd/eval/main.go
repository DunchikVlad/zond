// Command eval — генератор эталонного eval-датасета (blueprint п. 16.6,
// п. 16 п. 6): подкоманда generate собирает manifest.json + columns.jsonl
// по taxonomy.yaml. Метрики F1 и sweep порогов — следующие инкременты.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/evalset"
	"github.com/DunchikVlad/zond/internal/verdict"
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
	case "generate":
		return runGenerate(args[1:])
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "eval: неизвестная команда %q\n", args[0])
		usage()
		return 2
	}
}

// runGenerate — evalset.Generate по taxonomy.yaml + запись датасета.
// Ошибки — сообщение в stderr и код 2 (без паник), как в cmd/zond.
func runGenerate(args []string) int {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := fs.String("out", "evals/dataset", "каталог для manifest.json и columns.jsonl")
	taxonomyPath := fs.String("taxonomy", "configs/taxonomy.yaml", "путь к taxonomy.yaml (порядок лейблов датасета)")
	seed := fs.Int64("seed", 20261021, "seed детерминированной генерации (math/rand/v2 PCG)")
	rows := fs.Int("rows", 20, "значений на колонку")
	total := fs.Int("total", 1000, "колонок всего (positives + negatives)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	tax, err := config.LoadTaxonomy(*taxonomyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval generate: таксономия %s: %v\n", *taxonomyPath, err)
		return 2
	}
	labels := make([]verdict.Label, 0, len(tax.Labels))
	for _, l := range tax.Labels {
		labels = append(labels, verdict.Label(l.Name))
	}
	m, cols, err := evalset.Generate(evalset.Config{
		Seed:            *seed,
		Rows:            *rows,
		Total:           *total,
		Labels:          labels,
		TaxonomyVersion: tax.Version,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval generate: %v\n", err)
		return 2
	}
	if err := evalset.Write(*out, m, cols); err != nil {
		fmt.Fprintf(os.Stderr, "eval generate: %v\n", err)
		return 2
	}
	fmt.Printf("eval generate: OK (dataset v%s, taxonomy %s, seed %d, rows %d, total %d)\n",
		m.Dataset, m.Taxonomy, m.Seed, m.Rows, m.Total)
	fmt.Printf("по видам:")
	for _, k := range m.SortByKind() {
		fmt.Printf(" %s=%d", k, m.Counts.ByKind[k])
	}
	fmt.Println()
	fmt.Printf("файлы: %s/manifest.json, %s/columns.jsonl\n", *out, *out)
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "использование:")
	fmt.Fprintln(os.Stderr, "  eval generate [-out evals/dataset] [-taxonomy configs/taxonomy.yaml] [-seed 20261021] [-rows 20] [-total 1000]")
}
