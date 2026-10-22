// Command zond — классификатор данных в БД (blueprint п. 1, п. 15).
// Подкоманды: version, config validate, scan (этап 1 — вертикальный срез).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DunchikVlad/zond/internal/agentproxy"
	"github.com/DunchikVlad/zond/internal/analyze/meta"
	"github.com/DunchikVlad/zond/internal/api"
	"github.com/DunchikVlad/zond/internal/audit"
	"github.com/DunchikVlad/zond/internal/auth"
	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
	_ "github.com/DunchikVlad/zond/internal/connector/clickhouse" // регистрация по конвенции путей
	_ "github.com/DunchikVlad/zond/internal/connector/mongodb"    // регистрация по конвенции путей
	"github.com/DunchikVlad/zond/internal/doctor"
	"github.com/DunchikVlad/zond/internal/logging"
	"github.com/DunchikVlad/zond/internal/observe"
	"github.com/DunchikVlad/zond/internal/scanengine"
	"github.com/DunchikVlad/zond/internal/scheduler"
	"github.com/DunchikVlad/zond/internal/verdict"
	"github.com/DunchikVlad/zond/internal/verdict/store"
	"github.com/DunchikVlad/zond/internal/web"
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
	case "doctor":
		return runDoctor(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "token":
		return runToken(args[1:])
	case "serve":
		return runServe(args[1:])
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
	cfg := engineConfig(b)
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

// engineConfig собирает scanengine.Config из bundle конфигурации
// (общая точка для CLI `scan` и serve-runner'а, инкремент 5б).
func engineConfig(b *config.Bundle) scanengine.Config {
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
	return cfg
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
// serve (инкремент 5б, blueprint п. 11.2): REST API поверх Verdict Store.
// Аутентификация — инкремент 5в (SSO); до неё actor="api" и listen-адрес по
// умолчанию только loopback (ADR-impl-5б).
// ---------------------------------------------------------------------------

// engineRunner — api.ScanRunner поверх scanengine: асинхронные прогоны с
// мягкой остановкой через ctx (п. 11.2). Resource governance этапа 5:
// один активный прогон на источник (п. 13.2; per-source caps).
type engineRunner struct {
	b      *config.Bundle
	st     *store.Store
	log    *slog.Logger
	useLLM bool

	mu      sync.Mutex
	running map[string]context.CancelFunc // scan_id → cancel
	sources map[string]bool               // источник занят активным прогоном
}

func newEngineRunner(b *config.Bundle, st *store.Store, log *slog.Logger, useLLM bool) *engineRunner {
	return &engineRunner{
		b: b, st: st, log: log, useLLM: useLLM,
		running: map[string]context.CancelFunc{}, sources: map[string]bool{},
	}
}

// Start запускает прогон в фоне и возвращает scan_id сразу (п. 11.2 POST
// /scans → {scan_id}). Источник/профиль/подключение валидируются до старта —
// клиент получает осмысленную ошибку, а не «прогон умер в фоне».
// actor — автор аудит-событий прогона (п. 14.2: sso:<subject>/token:<id>/api).
func (r *engineRunner) Start(source, profile, actor string) (string, error) {
	src, err := findSource(r.b.Connections, source)
	if err != nil {
		return "", &api.BadScanRequestError{Reason: err.Error()}
	}
	if profile == "" {
		profile = r.b.Detectors.Scan.Profile
	}
	factory, ok := connector.Lookup(src.Type)
	if !ok {
		return "", &api.BadScanRequestError{Reason: fmt.Sprintf("коннектор %q не зарегистрирован", src.Type)}
	}
	dsn := src.DSN
	if dsn == "" {
		dsn = src.URI
	}
	conn, err := factory(dsn)
	if err != nil {
		return "", &api.SourceUnavailableError{Reason: fmt.Sprintf("источник %q: %v", source, err)}
	}
	if err := conn.Ping(context.Background()); err != nil {
		conn.Close()
		return "", &api.SourceUnavailableError{Reason: fmt.Sprintf("источник %q: %v", source, err)}
	}

	// LLM-слой собирается fail-fast до регистрации прогона (как `scan -llm`).
	var llm scanengine.LLMClassifier
	var llmID scanengine.LLMIdentity
	if r.useLLM {
		llm, llmID, err = buildLLMComposite(r.b, taxonomyLabels(r.b.Taxonomy))
		if err != nil {
			conn.Close()
			return "", &api.SourceUnavailableError{Reason: fmt.Sprintf("llm-слой: %v", err)}
		}
	}

	scanID := newAPIScanID()
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	if r.sources[source] {
		r.mu.Unlock()
		cancel()
		conn.Close()
		return "", &api.SourceUnavailableError{
			Reason: fmt.Sprintf("источник %q уже сканируется (1 активный прогон на источник, п. 13.2)", source),
		}
	}
	r.running[scanID] = cancel
	r.sources[source] = true
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.running, scanID)
			delete(r.sources, source)
			r.mu.Unlock()
			conn.Close()
		}()
		cfg := engineConfig(r.b)
		cfg.Actor = actor // п. 14.2: прогон аудируется от имени инициатора
		eng := scanengine.New(r.st, meta.New(r.b.Taxonomy.Synonyms), cfg)
		if llm != nil {
			eng.SetLLM(llm, llmID)
		}
		rep, err := eng.ScanWithID(ctx, conn, source, profile, scanID)
		if err != nil {
			r.log.Error("serve: прогон завершился ошибкой", "scan_id", scanID, "error", err)
			return
		}
		r.log.Info("serve: прогон завершён", "scan_id", scanID, "status", rep.Status)
	}()
	return scanID, nil
}

// Stop мягко останавливает прогон (отмена ctx; движок фиксирует interrupted,
// п. 11.2). Неизвестный/уже завершённый прогон — ошибка (API → 409).
func (r *engineRunner) Stop(scanID string) error {
	r.mu.Lock()
	cancel, ok := r.running[scanID]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("прогон %s не исполняется на этом сервере", scanID)
	}
	cancel()
	return nil
}

// newAPIScanID — идентификатор прогона API (тот же формат, что в движке:
// unix-hex; движок принимает id через ScanWithID).
func newAPIScanID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%d-%s", time.Now().Unix(), hex.EncodeToString(b[:]))
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fs.String("config", "configs", "каталог с конфигурационными файлами")
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	addr := fs.String("addr", "127.0.0.1:8080", "адрес HTTP-сервера (до SSO — только loopback, ADR-impl-5б)")
	exportMax := fs.Int("export-max-rows", 50000, "лимит строк экспорта (п. 11.2)")
	useLLM := fs.Bool("llm", false, "подключить LLM-слой при старте сканов через API")
	useSched := fs.Bool("scheduler", true, "запускать встроенный планировщик (TTL-кэш, retention, пересканы)")
	strict := fs.Bool("strict", false, "preflight doctor перед стартом: FAIL блокирует serve (п. 15.3)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *strict {
		b, err := config.LoadAll(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "serve -strict: конфигурация: %v\n", err)
			return 2
		}
		rep := doctor.Run(context.Background(), b, *dbPath, doctor.Options{Online: true})
		rep.Text(os.Stderr)
		if rep.HasFail() {
			fmt.Fprintln(os.Stderr, "serve -strict: preflight doctor не пройден — старт отменён (п. 15.3)")
			return 1
		}
	}
	log := logging.New(os.Stderr, "info")
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: конфигурация: %v\n", err)
		return 2
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: verdict store: %v\n", err)
		return 2
	}
	defer st.Close()

	runner := newEngineRunner(b, st, log, *useLLM)
	// Аутентификация (инкремент 5в, п. 11.3/п. 14.2): включается sso.enabled
	// в connections.yaml; admin-token fallback — env CLASSIFIER_ADMIN_TOKEN
	// при admin_token_fallback=true (bootstrap/аварийный доступ).
	sessions := auth.NewSessionStore(0)
	authCfg := api.AuthConfig{
		Enabled:  b.Connections.SSO.Enabled,
		Sessions: sessions,
	}
	if b.Connections.SSO.AdminTokenFallback {
		authCfg.AdminToken = os.Getenv("CLASSIFIER_ADMIN_TOKEN")
	}
	if authCfg.Enabled {
		log.Info("serve: аутентификация включена (SSO/API-токены)",
			"admin_token_fallback", authCfg.AdminToken != "")
	}
	var opts []api.Option
	opts = append(opts, api.WithRunner(runner), api.WithExportMaxRows(*exportMax), api.WithAuth(authCfg))
	// SAML SP (инкремент 5в-5, ADR-0011): метаданные IdP — при старте
	// (fail-fast при недоступности, п. 11.3), refresh каждые 24 ч.
	var sp *auth.SP
	if b.Connections.SSO.Enabled {
		metadataXML, err := auth.FetchMetadata(b.Connections.SSO.IDPMetadataURL, b.Connections.SSO.IDPMetadataFile, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			return 2
		}
		sp, err = auth.NewSP(auth.SAMLConfig{
			EntityID:       b.Connections.SSO.EntityID,
			ACSURL:         b.Connections.SSO.ACSURL,
			NameIDFormat:   b.Connections.SSO.NameIDFormat,
			RoleAttribute:  b.Connections.SSO.RoleAttribute,
			CookieSameSite: b.Connections.SSO.CookieSameSite,
			KeyFile:        b.Connections.SSO.SPKeyFile,
			CertFile:       b.Connections.SSO.SPCertificateFile,
			MetadataXML:    metadataXML,
		}, sessions, auth.Hooks{
			UpsertUser: func(ctx context.Context, rec auth.UserRec) error {
				return st.UpsertUser(ctx, &store.User{
					Subject: rec.Subject, DisplayName: rec.DisplayName,
					Role: string(rec.Role), LastLoginAt: time.Now().UTC(),
				}, time.Now().UTC())
			},
			Audit: func(ctx context.Context, actor, action, target string, details map[string]any) error {
				return st.AppendAudit(ctx, []audit.Event{{
					Actor: actor, Category: audit.CatAuth, Action: action, Target: target,
					Details: details, TS: time.Now().UTC(),
				}})
			},
			Log: func(msg string, args ...any) { log.Warn(msg, args...) },
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "serve: sso:", err)
			return 2
		}
		opts = append(opts, api.WithSAML(sp.Handler()))
		log.Info("serve: SAML SP готов", "entity_id", b.Connections.SSO.EntityID)
	}
	serveCtx, stopRefresh := context.WithCancel(context.Background())
	defer stopRefresh()
	if sp != nil {
		go sp.RunMetadataRefresh(serveCtx, b.Connections.SSO.IDPMetadataURL,
			b.Connections.SSO.IDPMetadataFile, nil, 24*time.Hour)
	}
	srv := api.New(st, log, opts...)
	// Веб-UI (инкремент 5г, п. 11.3): корневой mux — /api/ и /saml/ у
	// API-сервера, всё остальное (страницы) — у web-сервера (ADR-0007,
	// server-rendered + HTMX из embed.FS).
	webSrv, err := web.New(st, log, sessions, b.Connections.SSO.Enabled, runner, b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve: web:", err)
		return 2
	}
	root := http.NewServeMux()
	root.Handle("/api/", srv.Handler())
	root.Handle("/saml/", srv.Handler())
	root.Handle("/debug/vars", srv.Handler()) // expvar (п. 17) — у API-mux с auth
	root.Handle("/", webSrv.Handler())

	// Метрики инстанса в expvar (п. 17): zond/store — агрегаты за окно из
	// store, считаются на скрапе /debug/vars (дешёвые запросы SQLite).
	expvar.Publish("zond/store", expvar.Func(func() any {
		snap, err := observe.BuildSnapshot(context.Background(), st, observe.Default, observe.DefaultWindow)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return snap
	}))

	// Планировщик (инкремент 5г, п. 15/15.4): TTL-прочистка кэша, retention
	// сканов (90 дней), расписания пересканов источников (schedule).
	// Инкремент S6в: + оценка алертов (п. 17) каждые 5 минут; внешняя
	// доставка — webhook из ENV ZOND_ALERT_WEBHOOK (п. 12, п. 20).
	alertEval := observe.NewEvaluator(st, log,
		observe.WithWebhook(observe.NewWebhook(os.Getenv(observe.EnvWebhook), log)))
	sched := scheduler.New(st, runner, log, b.Connections.Sources,
		scheduler.WithAlerts("", alertEval.Eval))
	if *useSched {
		if err := sched.Start(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, "serve: scheduler:", err)
			return 2
		}
		defer sched.Stop()
		log.Info("serve: планировщик запущен")
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		sig := <-ch
		log.Info("serve: остановка", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()
	log.Info("serve: старт", "addr", *addr, "db", *dbPath, "llm", *useLLM)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// doctor (S7а: preflight перед вводом в эксплуатацию, blueprint п. 15.3)
// ---------------------------------------------------------------------------

// runDoctor — таблица OK/FAIL/WARN/SKIP по инстансу; код выхода 1 при любом
// FAIL (0 — всё чисто, 2 — ошибка использования/конфигурации).
func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	dir := fs.String("config", "configs", "каталог с конфигурационными файлами")
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	online := fs.Bool("online", false, "выполнить сетевые проверки (Ping источников, DNS и пробные вызовы агентов)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: конфигурация: %v\n", err)
		b = nil // отчёт всё равно строится: config.load FAIL + независимые проверки
	}
	rep := doctor.Run(context.Background(), b, *dbPath, doctor.Options{Online: *online})
	rep.Text(os.Stdout)
	if rep.HasFail() {
		return 1
	}
	return 0
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

// ---------------------------------------------------------------------------
// audit (инкремент 5а, ADR-0013): verify — пересчёт hash-chain; export —
// выгрузка событий (просмотр в штатном режиме — только роль admin, п. 14.2;
// без SSO actor="cli", RBAC приходит в этапе 5b).
// ---------------------------------------------------------------------------

func runAudit(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "zond audit: поддерживаются 'verify' и 'export'")
		return 2
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:])
	case "export":
		return runAuditExport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "zond audit: неизвестная подкоманда %q\n", args[0])
		return 2
	}
}

func runAuditVerify(args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit verify: store: %v\n", err)
		return 2
	}
	defer st.Close()
	rep, err := st.AuditVerify(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit verify: %v\n", err)
		return 2
	}
	if !rep.OK() {
		fmt.Printf("audit verify: FAIL — разрыв цепочки на seq=%d: %s (runbook: docs/runbooks/audit-hash-chain-broken.md)\n",
			rep.BrokenAt, rep.Reason)
		return 1
	}
	fmt.Printf("audit verify: OK (%d записей, hash-chain сходится)\n", rep.Checked)
	return 0
}

func runAuditExport(args []string) int {
	fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	actor := fs.String("actor", "", "фильтр: автор события")
	category := fs.String("category", "", "фильтр: категория (scan|agent|export|…)")
	since := fs.String("since", "", "фильтр: не раньше (RFC3339)")
	scanID := fs.String("scan", "", "фильтр: события скана")
	out := fs.String("out", "", "файл вывода (по умолчанию stdout)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var sinceT *time.Time
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit export: -since: %v (формат RFC3339)\n", err)
			return 2
		}
		sinceT = &t
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit export: store: %v\n", err)
		return 2
	}
	defer st.Close()
	f := audit.Filter{Actor: *actor, Category: *category, Since: sinceT, ScanID: *scanID}
	entries, err := st.AuditList(context.Background(), f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit export: выборка: %v\n", err)
		return 2
	}
	// Экспорт — аудируемое действие (п. 14.2): запись до выдачи данных;
	// ошибка аудита = экспорт не выполняется (fail-closed).
	if err := st.AppendAudit(context.Background(), []audit.Event{{
		Actor: "cli", Category: audit.CatExport, Action: "audit_export",
		Target: "export", TS: time.Now().UTC(),
		Details: map[string]any{
			"rows": len(entries), "format": "json",
			"filters": map[string]any{"actor": *actor, "category": *category, "since": *since, "scan": *scanID},
		},
	}}); err != nil {
		fmt.Fprintf(os.Stderr, "audit export: аудит экспорта: %v\n", err)
		return 2
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit export: сериализация: %v\n", err)
		return 2
	}
	if entries == nil {
		data = []byte("[]") // пустой журнал — валидный пустой массив, не null
	}
	if *out == "" {
		fmt.Println(string(data))
		return 0
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "audit export: запись файла: %v\n", err)
		return 2
	}
	fmt.Printf("audit export: OK (%d записей → %s)\n", len(entries), *out)
	return 0
}

// ---------------------------------------------------------------------------
// token (инкремент 5в-3, blueprint п. 14.2): API-токены программного доступа
// ---------------------------------------------------------------------------

func runToken(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "zond token: поддерживаются 'issue', 'list' и 'revoke'")
		return 2
	}
	switch args[0] {
	case "issue":
		return runTokenIssue(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "zond token: неизвестная подкоманда %q\n", args[0])
		return 2
	}
}

func runTokenIssue(args []string) int {
	fs := flag.NewFlagSet("token issue", flag.ContinueOnError)
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	name := fs.String("name", "", "имя токена (назначение, обязательно)")
	scopesCSV := fs.String("scopes", "read", "области через запятую: read,review,export,admin")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "срок действия (п. 14.2: default 90 дней)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *name == "" {
		fmt.Fprintln(os.Stderr, "token issue: флаг -name обязателен")
		return 2
	}
	var scopes []store.Scope
	for _, sc := range strings.Split(*scopesCSV, ",") {
		scopes = append(scopes, store.Scope(strings.TrimSpace(sc)))
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token issue: store: %v\n", err)
		return 2
	}
	defer st.Close()
	key := store.GenerateTokenKey()
	tok, err := st.IssueToken(context.Background(), store.NewCallID(), *name, scopes, key, "cli", time.Now().UTC(), *ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token issue: %v\n", err)
		return 2
	}
	// Ключ показывается ОДИН РАЗ (п. 14.2): в БД — только argon2id-хэш.
	fmt.Printf("token issue: OK (id %s, scopes %s, expires %s)\n", tok.ID, *scopesCSV, tok.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("ключ (показывается один раз, сохраните): %s\n", key)
	return 0
}

func runTokenList(args []string) int {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token list: store: %v\n", err)
		return 2
	}
	defer st.Close()
	toks, err := st.ListTokens(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "token list: %v\n", err)
		return 2
	}
	data, err := json.MarshalIndent(toks, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "token list: %v\n", err)
		return 2
	}
	if toks == nil {
		data = []byte("[]")
	}
	fmt.Println(string(data))
	return 0
}

func runTokenRevoke(args []string) int {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	id := fs.String("id", "", "id токена (обязательно)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" {
		fmt.Fprintln(os.Stderr, "token revoke: флаг -id обязателен")
		return 2
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "token revoke: store: %v\n", err)
		return 2
	}
	defer st.Close()
	if err := st.RevokeToken(context.Background(), *id, "cli", time.Now().UTC()); err != nil {
		fmt.Fprintf(os.Stderr, "token revoke: %v\n", err)
		return 2
	}
	fmt.Printf("token revoke: OK (%s отозван, действие мгновенное)\n", *id)
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "использование:")
	fmt.Fprintln(os.Stderr, "  zond version")
	fmt.Fprintln(os.Stderr, "  zond config validate [-dir configs]")
	fmt.Fprintln(os.Stderr, "  zond scan -source <имя> [-config configs] [-db zond.db] [-profile quick|deep|custom] [-llm]")
	fmt.Fprintln(os.Stderr, "  zond agent-check [-config configs] [-online]")
	fmt.Fprintln(os.Stderr, "  zond doctor [-config configs] [-db zond.db] [-online]")
	fmt.Fprintln(os.Stderr, "  zond audit verify [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond audit export [-db zond.db] [-actor x] [-category y] [-since RFC3339] [-scan id] [-out file]")
	fmt.Fprintln(os.Stderr, "  zond serve [-config configs] [-db zond.db] [-addr 127.0.0.1:8080] [-export-max-rows 50000] [-llm] [-scheduler] [-strict]")
	fmt.Fprintln(os.Stderr, "  zond token issue -name <имя> -scopes read,export [-ttl 2160h] [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond token list [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond token revoke -id <id> [-db zond.db]")
}
