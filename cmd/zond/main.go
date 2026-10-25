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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/DunchikVlad/zond/internal/secrets"
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
	case "backup":
		return runBackup(args[1:])
	case "restore":
		return runRestore(args[1:])
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
// secrets (S7в, ADR-0012): резолвер Vault для источников с ref.
// ---------------------------------------------------------------------------

// auditActorKey — actor аудит-события в контексте (п. 14.2): resolve секрета
// аудируется от имени инициатора, фоновое продление лиз — actor scheduler.
type auditActorKey struct{}

// secretsAuditHook — факт resolve/ротации секрета в audit-лог (п. 14.2,
// CatSecrets, без значений: только ref и path). Ошибка записи — warn:
// скан не роняем, но факт пропуска виден в логе.
func secretsAuditHook(st *store.Store, log *slog.Logger) secrets.AuditHook {
	return func(ctx context.Context, ref, path, action string) {
		actor, _ := ctx.Value(auditActorKey{}).(string)
		if action != secrets.ActionResolve {
			actor = "scheduler" // фоновое продление лиз (blueprint п. 14.2)
		}
		if actor == "" {
			actor = "cli"
		}
		if err := st.AppendAudit(ctx, []audit.Event{{
			Actor: actor, Category: audit.CatSecrets, Action: action,
			Target: "vault:" + ref, Details: map[string]any{"path": path},
			TS: time.Now().UTC(),
		}}); err != nil {
			log.Warn("аудит секретов: запись не удалась", "ref", ref, "action", action, "error", err)
		}
	}
}

// buildSecretsResolver — резолвер Vault по connections.yaml; выключенный
// Vault — (nil, nil): прежний режим ${ENV} (п. 12.1).
func buildSecretsResolver(ctx context.Context, b *config.Bundle, hook secrets.AuditHook) (secrets.Resolver, error) {
	if !b.Connections.Vault.Enabled {
		return nil, nil
	}
	return secrets.NewFromConfig(ctx, b.Connections.Vault, hook)
}

// resolveSourceDSN — DSN/URI источника: поля dsn/uri — как есть (ENV
// интерполированы при загрузке), ref — через резолвер Vault (ADR-0012).
func resolveSourceDSN(ctx context.Context, src *config.Source, r secrets.Resolver) (string, error) {
	if src.Ref == "" {
		dsn := src.DSN
		if dsn == "" {
			dsn = src.URI
		}
		return dsn, nil
	}
	if r == nil {
		return "", errors.New("vault не настроен (enabled=false), а источник ссылается ref")
	}
	return r.Resolve(ctx, src.Ref)
}

// secretsForRedact — значения env для redact-логирования (п. 14.1):
// переменные, названные конфигурацией (api_key_env агентов, token_env
// Vault), плюс эвристика имён (PASS/PWD/SECRET/TOKEN/KEY). Короткие (<6)
// значения redactor игнорирует.
func secretsForRedact(b *config.Bundle) []string {
	names := map[string]bool{}
	for _, a := range b.Detectors.Agents {
		names[a.APIKeyEnv] = true
	}
	if b.Connections.Vault.Enabled && b.Connections.Vault.Auth.TokenEnv != "" {
		names[b.Connections.Vault.Auth.TokenEnv] = true
	}
	var out []string
	for name := range names {
		if v := os.Getenv(name); v != "" {
			out = append(out, v)
		}
	}
	heuristic := regexp.MustCompile(`(?i)(pass|pwd|secret|token|apikey|private)`)
	for _, e := range os.Environ() {
		name, value, _ := strings.Cut(e, "=")
		if len(value) >= 6 && heuristic.MatchString(name) {
			out = append(out, value)
		}
	}
	return out
}

// redactedLogger — JSON-логгер stderr с redact middleware (п. 14.1):
// секреты по конфигу и эвристике имён env не попадают в лог.
func redactedLogger(b *config.Bundle) *slog.Logger {
	return logging.New(os.Stderr, "info", logging.NewSecretRedactor(secretsForRedact(b)...))
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
	resume := fs.Bool("resume", false, "догнать последний partial/interrupted прогон источника (пропустить done-таблицы, п. 13.2)")
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
	// Store до подключения: resolve секрета (ref) аудируется в hash-chain
	// (п. 14.2), actor cli.
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: verdict store: %v\n", err)
		return 2
	}
	defer st.Close()
	log := redactedLogger(b)
	resolver, err := buildSecretsResolver(context.Background(), b, secretsAuditHook(st, log))
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: vault: %v\n", err)
		return 2
	}
	if resolver != nil {
		defer resolver.Close()
	}
	factory, ok := connector.Lookup(src.Type)
	if !ok {
		fmt.Fprintf(os.Stderr, "scan: коннектор %q не зарегистрирован (доступно: %v)\n", src.Type, connector.Types())
		return 2
	}
	ctx := context.WithValue(context.Background(), auditActorKey{}, "cli")
	dsn, err := resolveSourceDSN(ctx, src, resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: подключение: %v\n", err)
		return 2
	}
	conn, err := factory(dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan: подключение: %v\n", err)
		return 2
	}
	defer conn.Close()

	prof := *profile
	if prof == "" {
		prof = b.Detectors.Scan.Profile
	}
	cfg := engineConfig(b)
	// Circuit breaker (п. 13.2): в CLI экземпляр на процесс — срабатывание
	// внутри прогона корректно; в serve шарится между прогонами (runner).
	cfg.Breaker = scanengine.NewBreaker()
	// Лимиты источника (п. 13.2, S8-2): таблицы параллельно до
	// max_concurrent_tables, дедлайн запроса к БД — query_timeout_s.
	// max_concurrent_scans в CLI не применим — один прогон на процесс.
	cfg.MaxTables = src.TablesLimit()
	cfg.QueryTimeout = src.QueryTimeout()
	if *resume {
		prev, err := st.LastCheckpointScan(context.Background(), src.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: -resume: %v\n", err)
			return 2
		}
		if prev == nil {
			fmt.Fprintf(os.Stderr, "scan: -resume: нет partial/interrupted прогона для источника %q\n", src.Name)
			return 2
		}
		cfg.ResumeFrom = prev.ID
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

// auditSinkConfig — конверт connections.yaml audit.sink в контракт
// воркера (internal/audit не тянет config, п. 14.2). Пустой блок → нулевой
// конфиг → sink выключен (NewSink вернёт nil).
func auditSinkConfig(c config.SinkConfig) audit.SinkConfig {
	return audit.SinkConfig{
		Kind:    audit.SinkKind(c.Kind),
		Address: c.Address,
		Proto:   string(c.Proto),
	}
}

// sinkLoop — цикл воркера SIEM-sink (S8-3, п. 14.2): Pump по таймеру 2 с;
// при ошибке уровня журнала (недоступна БД/закладка) — пауза 30 с между
// циклами. Недоступность самого sink не ошибка Pump: закладка не двигается,
// следующий цикл повторит (потеря исключена — очередь = журнал). Остановка
// — по ctx serve; in-flight Pump дожидается сам.
func sinkLoop(ctx context.Context, sink *audit.Sink) {
	const (
		tick    = 2 * time.Second
		backoff = 30 * time.Second
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
		if _, err := sink.Pump(ctx); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
		}
	}
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
// мягкой остановкой через ctx (п. 11.2). Resource governance (п. 13.2):
// max_concurrent_scans источника (семафоры map, default 1) и общий
// circuit breaker процесса (инкремент 8-1).
type engineRunner struct {
	b        *config.Bundle
	st       *store.Store
	log      *slog.Logger
	useLLM   bool
	resolver secrets.Resolver // ref-источников (Vault, ADR-0012); nil — режим ENV
	breaker  *scanengine.Breaker
	connsFn  func() *config.Connections // S8-7: горячий провайдер (UI-правка); nil — статика

	mu       sync.Mutex
	running  map[string]context.CancelFunc // scan_id → cancel
	srcSlots map[string]chan struct{}      // source → семафор max_concurrent_scans (п. 13.2)
}

// conns — текущие connections (горячие при UI-правке, иначе из cfg).
func (r *engineRunner) conns() *config.Connections {
	if r.connsFn != nil {
		if c := r.connsFn(); c != nil {
			return c
		}
	}
	return r.b.Connections
}

func newEngineRunner(b *config.Bundle, st *store.Store, log *slog.Logger, useLLM bool, resolver secrets.Resolver) *engineRunner {
	return &engineRunner{
		b: b, st: st, log: log, useLLM: useLLM, resolver: resolver,
		breaker:  scanengine.NewBreaker(),
		running:  map[string]context.CancelFunc{},
		srcSlots: map[string]chan struct{}{},
	}
}

// Start запускает прогон в фоне и возвращает scan_id сразу (п. 11.2 POST
// /scans → {scan_id}). Источник/профиль/подключение валидируются до старта —
// клиент получает осмысленную ошибку, а не «прогон умер в фоне».
// actor — автор аудит-событий прогона (п. 14.2: sso:<subject>/token:<id>/api).
func (r *engineRunner) Start(source, profile, actor string) (string, error) {
	src, err := findSource(r.conns(), source)
	if err != nil {
		return "", &api.BadScanRequestError{Reason: err.Error()}
	}
	// Circuit breaker (п. 13.2): источник на паузе — отказ до подключения.
	if perr := r.breaker.PausedErr(source, time.Now()); perr != nil {
		return "", &api.SourceUnavailableError{Reason: perr.Error()}
	}
	if profile == "" {
		profile = r.b.Detectors.Scan.Profile
	}
	factory, ok := connector.Lookup(src.Type)
	if !ok {
		return "", &api.BadScanRequestError{Reason: fmt.Sprintf("коннектор %q не зарегистрирован", src.Type)}
	}
	// Resolve ref (Vault) от имени инициатора: факт — в аудит (п. 14.2).
	dsnCtx := context.WithValue(context.Background(), auditActorKey{}, actor)
	dsn, err := resolveSourceDSN(dsnCtx, src, r.resolver)
	if err != nil {
		reason := fmt.Sprintf("источник %q: %v", source, err)
		if errors.Is(err, secrets.ErrUnavailable) {
			reason = fmt.Sprintf("источник %q: vault_unavailable: %v", source, err)
		}
		return "", &api.SourceUnavailableError{Reason: reason}
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
	// max_concurrent_scans источника (п. 13.2, S8-2): семафор процесса
	// (default 1); слот занят активным прогоном до его завершения.
	slots, ok := r.srcSlots[source]
	if !ok {
		slots = make(chan struct{}, src.ScansLimit())
		r.srcSlots[source] = slots
	}
	select {
	case slots <- struct{}{}:
	default:
		r.mu.Unlock()
		cancel()
		conn.Close()
		return "", &api.SourceUnavailableError{
			Reason: fmt.Sprintf("источник %q: лимит max_concurrent_scans=%d исчерпан (п. 13.2)", source, cap(slots)),
		}
	}
	r.running[scanID] = cancel
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.running, scanID)
			<-slots // освобождение слота max_concurrent_scans (п. 13.2)
			r.mu.Unlock()
			conn.Close()
		}()
		cfg := engineConfig(r.b)
		cfg.Actor = actor // п. 14.2: прогон аудируется от имени инициатора
		cfg.Breaker = r.breaker
		// Лимиты источника (п. 13.2, S8-2): таблицы параллельно до
		// max_concurrent_tables, дедлайн запроса к БД — query_timeout_s.
		cfg.MaxTables = src.TablesLimit()
		cfg.QueryTimeout = src.QueryTimeout()
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
	b, err := config.LoadAll(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: конфигурация: %v\n", err)
		return 2
	}
	// S8-7: горячий провайдер connections — после правки источников через UI
	// (/sources) файл перечитывается, держатель меняется, расписания
	// шедулера перестраиваются; действующие прогоны не трогаем.
	var connsHot atomic.Pointer[config.Connections]
	connsHot.Store(b.Connections)
	connsPath := filepath.Join(*dir, "connections.yaml")
	var sched *scheduler.Scheduler
	applyConns := func(config.SourceEntry) (*config.Connections, error) {
		c, err := config.LoadConnections(connsPath)
		if err != nil {
			return nil, err // файл записан, но не применён (например, новый ENV) — вступит после рестарта
		}
		connsHot.Store(c)
		if sched != nil {
			sched.ReplaceSources(c.Sources)
		}
		return c, nil
	}
	log := redactedLogger(b)
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: verdict store: %v\n", err)
		return 2
	}
	defer st.Close()

	// Секреты подключений (S7в, ADR-0012): resolver для ref-источников,
	// аудит resolve/ротации — в hash-chain (actor из контекста/scheduler).
	resolver, err := buildSecretsResolver(context.Background(), b, secretsAuditHook(st, log))
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: vault: %v\n", err)
		return 2
	}
	if resolver != nil {
		defer resolver.Close()
		log.Info("serve: секреты подключений — Vault", "address", b.Connections.Vault.Address,
			"refs", len(b.Connections.Vault.Secrets))
	}
	runner := newEngineRunner(b, st, log, *useLLM, resolver)
	runner.connsFn = connsHot.Load // S8-7: горячий список источников
	// Аутентификация (инкремент 5в, п. 11.3/п. 14.2): включается sso.enabled
	// в connections.yaml; admin-token fallback — env CLASSIFIER_ADMIN_TOKEN
	// при admin_token_fallback=true (bootstrap/аварийный доступ).
	sessions := auth.NewSessionStore(0)
	authCfg := api.AuthConfig{
		Enabled:  b.Connections.SSO.Enabled,
		Sessions: sessions,
		// Rate-limit входа (п. 14, brute-force admin-токена): 5 неудач за
		// 10 мин → блокировка 15 мин (Defaults, S7г).
		Limiter: auth.NewAttemptLimiter(auth.LimiterMaxFails, auth.LimiterWindow, auth.LimiterBlockFor),
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
	webSrv, err := web.New(st, log, sessions, b.Connections.SSO.Enabled, runner, b,
		web.WithConns(connsHot.Load),
		web.WithConnsPath(connsPath),
		web.WithApplyConns(applyConns),
	)
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
	backupConfigured := b.Connections.Backup.Schedule != ""
	alertEval := observe.NewEvaluator(st, log,
		observe.WithWebhook(observe.NewWebhook(os.Getenv(observe.EnvWebhook), log)),
		observe.WithBackupExpected(backupConfigured))
	schedOpts := []scheduler.Option{scheduler.WithAlerts("", alertEval.Eval)}
	if backupConfigured {
		// Расписание копий Verdict Store (п. 15.2): VACUUM INTO в backup.dir.
		schedOpts = append(schedOpts, scheduler.WithBackup(b.Connections.Backup.Schedule, b.Connections.Backup.Dir))
	}
	sched = scheduler.New(st, runner, log, b.Connections.Sources, schedOpts...)
	if *useSched {
		if err := sched.Start(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, "serve: scheduler:", err)
			return 2
		}
		defer sched.Stop()
		log.Info("serve: планировщик запущен")
	}

	// SIEM-sink (S8-3, п. 14.2): внешний sink аудит-журнала (опция
	// `audit.sink` в connections.yaml). Очередь — сам журнал (append-only);
	// воркер держит закладку audit_sink_state и двигает её только за
	// доставленное: потеря событий недопустима. Недоступность sink не
	// роняет запись аудита (fail-closed по журналу, не по sink).
	sink := audit.NewSink(st.DB(), auditSinkConfig(b.Connections.Audit.Sink), log)
	if sink.Enabled() {
		go sinkLoop(serveCtx, sink)
		log.Info("serve: SIEM-sink запущен", "kind", sink.Kind(),
			"address", b.Connections.Audit.Sink.Address)
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
// backup (S7б-1: онлайн-копия Verdict Store, blueprint п. 15.2)
// ---------------------------------------------------------------------------

// runBackup — `zond backup --out <path>`: VACUUM INTO без остановки
// сервиса; факт копии (успех/неудача с ошибкой) — в аудит-лог (п. 14.2,
// actor cli) — записи читает правило алертинга backup_failed (п. 17).
func runBackup(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	dbPath := fs.String("db", "zond.db", "файл Verdict Store (SQLite)")
	out := fs.String("out", "", "путь копии (обязателен; существующий файл не перезаписывается)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "backup: флаг -out обязателен")
		return 2
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: store: %v\n", err)
		return 1
	}
	defer st.Close()
	start := time.Now()
	size, err := st.Backup(context.Background(), *out)
	dur := time.Since(start).Round(time.Millisecond)
	details := map[string]any{"path": *out, "duration_ms": dur.Milliseconds()}
	if err != nil {
		details["status"] = "fail"
		details["error"] = err.Error()
		_ = st.AppendAudit(context.Background(), []audit.Event{{
			Actor: "cli", Category: audit.CatAdmin, Action: "backup",
			Target: "backup:" + *out, Details: details, TS: time.Now().UTC(),
		}})
		fmt.Fprintf(os.Stderr, "backup: %v\n", err)
		return 1
	}
	details["status"] = "ok"
	details["bytes"] = size
	if err := st.AppendAudit(context.Background(), []audit.Event{{
		Actor: "cli", Category: audit.CatAdmin, Action: "backup",
		Target: "backup:" + *out, Details: details, TS: time.Now().UTC(),
	}}); err != nil {
		fmt.Fprintf(os.Stderr, "backup: аудит: %v\n", err)
		return 1
	}
	fmt.Printf("backup: OK (%s, %d байт, %s)\n", *out, size, dur)
	return 0
}

// ---------------------------------------------------------------------------
// restore (S7б-2: учебное восстановление из копии, DoD п. 22 / п. 15.2)
// ---------------------------------------------------------------------------

// runRestore — `zond restore --from <copy> --to <dir>`: копия переносится
// в пустой каталог как zond.db, открывается (goose up = migrate), цепочка
// аудита пересчитывается. Это автоматизация учебного восстановления из DoD.
func runRestore(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	from := fs.String("from", "", "файл копии (обязателен)")
	to := fs.String("to", "", "пустой каталог восстановления (обязателен)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "restore: флаги -from и -to обязательны")
		return 2
	}
	if _, err := os.Stat(*from); err != nil {
		fmt.Fprintf(os.Stderr, "restore: копия %s: %v\n", *from, err)
		return 1
	}
	if err := os.MkdirAll(*to, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "restore: каталог: %v\n", err)
		return 1
	}
	dst := filepath.Join(*to, "zond.db")
	if _, err := os.Stat(dst); err == nil {
		fmt.Fprintf(os.Stderr, "restore: %s уже существует — каталог не пустой (fail-closed)\n", dst)
		return 1
	}
	raw, err := os.ReadFile(*from)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: чтение копии: %v\n", err)
		return 1
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "restore: запись: %v\n", err)
		return 1
	}
	st, err := store.Open(dst) // migrate на копии (DoD: migrate + hash-chain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: открытие восстановленной БД: %v\n", err)
		return 1
	}
	defer st.Close()
	rep, err := st.AuditVerify(context.Background())
	if err != nil || !rep.OK() {
		fmt.Fprintf(os.Stderr, "restore: hash-chain аудита: %v (%+v)\n", err, rep)
		return 1
	}
	fmt.Printf("restore: OK (%s: %d записей аудита, цепочка сходится)\n", dst, rep.Checked)
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
	fmt.Fprintln(os.Stderr, "  zond scan -source <имя> [-config configs] [-db zond.db] [-profile quick|deep|custom] [-llm] [-resume]")
	fmt.Fprintln(os.Stderr, "  zond agent-check [-config configs] [-online]")
	fmt.Fprintln(os.Stderr, "  zond doctor [-config configs] [-db zond.db] [-online]")
	fmt.Fprintln(os.Stderr, "  zond backup -out <path> [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond restore -from <копия> -to <пустой каталог>")
	fmt.Fprintln(os.Stderr, "  zond audit verify [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond audit export [-db zond.db] [-actor x] [-category y] [-since RFC3339] [-scan id] [-out file]")
	fmt.Fprintln(os.Stderr, "  zond serve [-config configs] [-db zond.db] [-addr 127.0.0.1:8080] [-export-max-rows 50000] [-llm] [-scheduler] [-strict]")
	fmt.Fprintln(os.Stderr, "  zond token issue -name <имя> -scopes read,export [-ttl 2160h] [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond token list [-db zond.db]")
	fmt.Fprintln(os.Stderr, "  zond token revoke -id <id> [-db zond.db]")
}
