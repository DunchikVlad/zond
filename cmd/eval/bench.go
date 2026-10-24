// Подкоманда bench — нагрузочный тест слоя 1 (blueprint п. 16.8):
// 1M детерминированных синтетических значений через rules.Analyze
// (зеркало пути scanengine), сверка с NFR п. 18 (≥100 000 значений/мин
// на ядро). Код выхода 1 при провале NFR — используется как CI-гейт.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/DunchikVlad/zond/internal/analyze/rules"
	"github.com/DunchikVlad/zond/internal/benchlab"
)

func runBench(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	n := fs.Int("n", 1_000_000, "всего синтетических значений")
	seed := fs.Int64("seed", 20261024, "seed детерминированной генерации (math/rand/v2 PCG)")
	colSize := fs.Int("col-size", 1000, "значений в «колонке» (один вызов rules.Analyze)")
	pos := fs.Float64("pos", 0.25, "доля позитивов (остальное — негативы)")
	threshold := fs.Float64("threshold", 0, "порог NFR, значений/мин на ядро (0 — по умолчанию 100000)")
	out := fs.String("out", "evals/reports/bench.json", "куда писать JSON-отчёт (\"\" — не писать)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	rep, err := benchlab.Run(rules.Default(), benchlab.Config{
		Total: *n, Seed: *seed, ColSize: *colSize, PosShare: *pos, Threshold: *threshold,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval bench: %v\n", err)
		return 2
	}

	if *out != "" {
		if err := benchlab.WriteReport(*out, rep); err != nil {
			fmt.Fprintf(os.Stderr, "eval bench: %v\n", err)
			return 2
		}
	}

	fmt.Printf("eval bench: %d значений (%d позитивов / %d негативов), seed %d, колонки по %d\n",
		rep.Generated.Total, rep.Generated.Positives, rep.Generated.Negatives, rep.Generated.Seed, rep.Generated.ColSize)
	for _, m := range rep.Matches {
		fmt.Printf("  %-18s matched %d\n", m.RecognizerID, m.Matched)
	}
	fmt.Printf("прогон: %d значений за %.0f мс → %.0f знач/с (%.0f знач/мин на ядро)\n",
		rep.Generated.Total, rep.DurationMS, rep.ValuesPerSec, rep.ValuesPerMin)
	if rep.NFRPass {
		fmt.Printf("NFR п. 18: OK (порог %.0f знач/мин на ядро)\n", rep.NFRValuesPerMinPerCore)
	} else {
		fmt.Fprintf(os.Stderr, "NFR п. 18: ПРОВАЛ — %.0f < %.0f знач/мин на ядро\n",
			rep.ValuesPerMin, rep.NFRValuesPerMinPerCore)
	}
	if *out != "" {
		fmt.Printf("отчёт: %s\n", *out)
	}
	if !rep.NFRPass {
		return 1
	}
	return 0
}
