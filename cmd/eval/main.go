// Command eval — инструментарий этапа 6 (blueprint п. 16.6): generate —
// генератор эталонного eval-датасета; run — eval-harness (прогон каскада
// по датасету, P/R/F1 по лейблам, sweep tau_accept, отчёт «$/1000 колонок»).
// Отдельный бинарь: контур этапа 6 не трогает store, секреты (кроме ключа
// LLM-агента) и SSO (ADR-impl-6а D1).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/ensemble"
	"github.com/DunchikVlad/zond/internal/evalharness"
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
	case "run":
		return runHarness(args[1:])
	case "bench":
		return runBench(args[1:])
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

// runHarness — прогон каскада по датасету + JSON-отчёт (blueprint п. 16.6).
// По умолчанию слои 0+1+ensemble (детерминированно, без сети — для CI);
// с -llm подключается agent-proxy по реестру detectors.yaml (fail-fast без
// ключа; egress-политика и лимиты — как у zond scan, п. 10.4/10.7).
func runHarness(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	datasetDir := fs.String("dataset", "evals/dataset", "каталог с manifest.json и columns.jsonl")
	taxonomyPath := fs.String("taxonomy", "configs/taxonomy.yaml", "путь к taxonomy.yaml (словарь слоя 0, лейблы для LLM)")
	detectorsPath := fs.String("detectors", "configs/detectors.yaml", "путь к detectors.yaml (пороги, веса, реестр агентов)")
	llmOn := fs.Bool("llm", false, "включить слой 2 (LLM через agent-proxy); без флага — слои 0+1+ensemble")
	agentID := fs.String("agent", "", "id агента из detectors.yaml (по умолчанию — первый; только с -llm)")
	endpoint := fs.String("endpoint", "", "переопределить endpoint агента (например локальный стенд; только с -llm)")
	priceIn := fs.Float64("price-in", 0, "цена входящих токенов $/1M (учёт $/1000 колонок; 0 — без цены)")
	priceOut := fs.Float64("price-out", 0, "цена исходящих токенов $/1M (0 — без цены)")
	out := fs.String("out", "evals/reports/report.json", "куда писать JSON-отчёт")
	limit := fs.Int("limit", 0, "первые N колонок датасета (0 — все)")
	tauGrid := fs.String("tau-grid", "0.50:0.05:0.95", "сетка sweep tau_accept: от:шаг:до")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	grid, err := parseGrid(*tauGrid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval run: %v\n", err)
		return 2
	}
	tax, err := config.LoadTaxonomy(*taxonomyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval run: таксономия %s: %v\n", *taxonomyPath, err)
		return 2
	}
	det, err := config.LoadDetectors(*detectorsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval run: детекторы %s: %v\n", *detectorsPath, err)
		return 2
	}
	m, cols, err := evalset.Read(*datasetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval run: датасет %s: %v\n", *datasetDir, err)
		return 2
	}
	if *limit > 0 && *limit < len(cols) {
		cols = cols[:*limit]
	}

	cfg := evalharness.Config{
		TauAccept: det.Ensemble.TauAccept,
		TauReview: det.Ensemble.TauReview,
		Weights:   ensemble.Weights{},
		Meta:      meta.New(tax.Synonyms),
		Prices:    evalharness.Prices{In: *priceIn, Out: *priceOut},
	}
	for k, w := range det.Ensemble.Weights {
		cfg.Weights[verdict.EvidenceLayer(k)] = w
	}

	var llm evalharness.LLMClassifier
	agentIDVal, modelVal := "", ""
	if *llmOn {
		llm, agentIDVal, modelVal, err = buildLLM(det, tax, *agentID, *endpoint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "eval run: LLM-слой: %v\n", err)
			return 2
		}
		cfg.LLM = llm
		cfg.Band = agentBand(det, agentIDVal)
		fmt.Printf("eval run: LLM-слой: агент %s (модель %s), серый коридор [%g %g]\n",
			agentIDVal, modelVal, cfg.Band[0], cfg.Band[1])
	}

	start := time.Now()
	rr, err := evalharness.Run(context.Background(), cols, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "eval run: прогон: %v\n", err)
		return 2
	}
	rep := evalharness.BuildReport(m, cols, rr, cfg, grid, *datasetDir, agentIDVal, modelVal)
	if err := evalharness.WriteReport(*out, rep); err != nil {
		fmt.Fprintf(os.Stderr, "eval run: %v\n", err)
		return 2
	}
	rep.Text(os.Stdout)
	fmt.Printf("прогон: %d колонок за %s; отчёт: %s\n", len(cols), time.Since(start).Round(time.Millisecond), *out)
	return 0
}

// buildLLM — прокси основного агента и верификатор (escalate_to) с общим
// Gate лимитов и egress-политикой — зеркало buildLLMComposite cmd/zond
// (п. 10.4, п. 10.7, fail-fast).
func buildLLM(det *config.Detectors, tax *config.Taxonomy, agentID, endpointOverride string) (evalharness.LLMClassifier, string, string, error) {
	agents := det.Agents
	if len(agents) == 0 {
		return nil, "", "", fmt.Errorf("реестр agents пуст (detectors.yaml)")
	}
	main := agents[0]
	if agentID != "" {
		found := false
		for i := range agents {
			if agents[i].ID == agentID {
				main = agents[i]
				found = true
				break
			}
		}
		if !found {
			return nil, "", "", fmt.Errorf("агент %q не найден в реестре detectors.yaml", agentID)
		}
	}
	labels := make([]string, 0, len(tax.Labels))
	for _, l := range tax.Labels {
		labels = append(labels, l.Name)
	}
	gate := agentproxy.NewGate(det.Proxy.MaxConcurrent, det.Proxy.RateLimitRPS)
	mainProxy, err := newProxy(main, labels, tax.Version, gate, det.Proxy.Offline, endpointOverride)
	if err != nil {
		return nil, "", "", err
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
		if esc == nil {
			return nil, "", "", fmt.Errorf("escalate_to=%q не найден в реестре", main.EscalateTo)
		}
		verifyProxy, err = newProxy(*esc, labels, tax.Version, gate, det.Proxy.Offline, "")
		if err != nil {
			return nil, "", "", err
		}
	}
	return &llmComposite{classify: mainProxy, verify: verifyProxy}, main.ID, main.Model, nil
}

// newProxy — конструкция прокси агента: ключ из env (fail-fast), лимиты,
// egress-политика; endpointOverride — для локального стенда (fake-LLM).
func newProxy(a config.AgentSpec, labels []string, taxVersion string, gate *agentproxy.Gate, offline bool, endpointOverride string) (*agentproxy.Proxy, error) {
	key := os.Getenv(a.APIKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("env %s не задан (api_key_env агента %s)", a.APIKeyEnv, a.ID)
	}
	endpoint := a.Endpoint
	if endpointOverride != "" {
		endpoint = endpointOverride
	}
	return agentproxy.New(agentproxy.Agent{
		ID: a.ID, Endpoint: endpoint, Model: a.Model, APIKey: key,
		MaxValuesPerCall: a.MaxValuesPerCall, Timeout: time.Duration(a.TimeoutS) * time.Second,
		MaxRetries: a.MaxRetries,
	}, labels, taxVersion,
		agentproxy.WithGate(gate),
		agentproxy.WithPolicy(agentproxy.Policy{Offline: offline, Allowlist: a.Allowlist}),
	)
}

// agentBand — confidence_band агента для серой зоны эскалации; пустой —
// harness берёт [tau_review, tau_accept] (bandOf).
func agentBand(det *config.Detectors, agentID string) [2]float64 {
	for _, a := range det.Agents {
		if a.ID == agentID {
			return a.ConfidenceBand
		}
	}
	return [2]float64{}
}

// llmComposite — композиция прокси под интерфейс harness'а (как cmd/zond).
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

// parseGrid — разбор "от:шаг:до" в сетку tau_accept (значения в (0,1],
// монотонная). Пустая строка → без sweep.
func parseGrid(s string) ([]float64, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("tau-grid %q: формат от:шаг:до", s)
	}
	lo, err1 := strconv.ParseFloat(parts[0], 64)
	step, err2 := strconv.ParseFloat(parts[1], 64)
	hi, err3 := strconv.ParseFloat(parts[2], 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, fmt.Errorf("tau-grid %q: числа с плавающей точкой", s)
	}
	if lo <= 0 || hi > 1 || step <= 0 || lo > hi {
		return nil, fmt.Errorf("tau-grid %q: ожидалось 0<от<=до<=1, шаг>0", s)
	}
	var grid []float64
	for v := lo; v <= hi+1e-9; v += step {
		grid = append(grid, v)
	}
	return grid, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "использование:")
	fmt.Fprintln(os.Stderr, "  eval generate [-out evals/dataset] [-taxonomy configs/taxonomy.yaml] [-seed 20261021] [-rows 20] [-total 1000]")
	fmt.Fprintln(os.Stderr, "  eval run [-dataset evals/dataset] [-taxonomy configs/taxonomy.yaml] [-detectors configs/detectors.yaml]")
	fmt.Fprintln(os.Stderr, "           [-llm [-agent id] [-endpoint URL]] [-price-in 0] [-price-out 0]")
	fmt.Fprintln(os.Stderr, "           [-out evals/reports/report.json] [-limit 0] [-tau-grid 0.50:0.05:0.95]")
	fmt.Fprintln(os.Stderr, "  eval bench [-n 1000000] [-seed 20261024] [-col-size 1000] [-pos 0.25] [-threshold 0]")
	fmt.Fprintln(os.Stderr, "             [-out evals/reports/bench.json]")
}
