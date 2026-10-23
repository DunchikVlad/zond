// Vault-реализация Resolver (ADR-0012, blueprint п. 12.1): чтение kv-v2 и
// dynamic leases, кэш лиз в памяти до истечения (R11), фоновое продление.
// Значения секретов нигде не сохраняются: только в полях структур на время
// жизни лизы. net/http здесь не импортируется (depguard) — транспорт у
// hashicorp/vault/api.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// defaultLease — длительность кэша, если Vault вернул лизу без срока
// (несоответствие протоколу; короткий срок = fail-safe).
const defaultLease = time.Minute

// Path продления лиз (sys/renew/<lease_id>).
const renewPath = "sys/renew/"

// Entry — одна запись vault.secrets: путь чтения и ровно один режим
// (key — kv-v2, DSNTemplate — dynamic database/creds).
type Entry struct {
	Path        string
	Key         string
	DSNTemplate string
}

// Config — параметры Vault-резолвера. Token — уже разрешённый клиентский
// токен (Authenticate); Secrets — ref → запись.
type Config struct {
	Address string
	Token   string
	Secrets map[string]Entry
	// Audit — факт резолва/ротации без значений (nil — без аудита).
	Audit AuditHook
	// Now — «сейчас» для тестов съёмки времени; nil — time.Now.
	Now func() time.Time
	// Timeout — сетевой таймаут вызовов к Vault; 0 — 10 с.
	Timeout time.Duration
}

// leaseMeta — срок жизни динамической лизы.
type leaseMeta struct {
	id        string
	renewable bool
	duration  time.Duration
}

// cacheEntry — закэшированный секрет динамической лизы (R11: до истечения).
type cacheEntry struct {
	value     string
	leaseID   string
	expiresAt time.Time
}

// Vault — Resolver поверх HashiCorp Vault.
type Vault struct {
	cfg    Config
	client *vaultapi.Client

	mu     sync.Mutex
	cache  map[string]cacheEntry         // ref → лиза (только dynamic)
	cancel map[string]context.CancelFunc // ref → остановка renewer'а лизы
	ctx    context.Context               // общая остановка (Close)
	stop   context.CancelFunc
	wg     sync.WaitGroup

	now func() time.Time
}

// NewVault строит резолвер: клиент vault/api по Config, без обращений к
// сети (первый вызов — Resolve/Authenticate).
func NewVault(cfg Config) (*Vault, error) {
	if cfg.Address == "" {
		return nil, errors.New("secrets: vault address пуст")
	}
	if cfg.Token == "" {
		return nil, errors.New("secrets: vault token пуст (Authenticate)")
	}
	client, err := newClient(cfg.Address, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	client.SetToken(cfg.Token)
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client.SetClientTimeout(timeout)
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Vault{
		cfg: cfg, client: client,
		cache: map[string]cacheEntry{}, cancel: map[string]context.CancelFunc{},
		ctx: ctx, stop: stop, now: now,
	}, nil
}

// Resolve — DSN/URI для ref. kv-v2 (key) читается на каждый коннект
// (ротация — на стороне Vault); dynamic (dsn_template) — из кэша лизы,
// пока она не истекла, иначе — свежий запрос (прозрачная смена секрета
// без перезапуска сервиса, п. 12.1).
func (v *Vault) Resolve(ctx context.Context, ref string) (string, error) {
	e, ok := v.cfg.Secrets[ref]
	if !ok {
		return "", fmt.Errorf("secrets: ref %q не настроен в vault.secrets", ref)
	}
	if e.Key != "" {
		// kv-v2: кэширование не применяется — значение дочитвается
		// при каждом установлении коннекта (авто-ротация в Vault).
		val, _, err := v.fetch(ctx, e)
		if err != nil {
			return "", fmt.Errorf("%w: ref %q: %v", ErrUnavailable, ref, err)
		}
		v.audit(ctx, ref, e.Path, ActionResolve)
		return val, nil
	}
	v.mu.Lock()
	c, ok := v.cache[ref]
	v.mu.Unlock()
	if ok && v.now().Before(c.expiresAt) {
		return c.value, nil // лиза валидна — сеть не трогаем (R11)
	}
	val, lease, err := v.fetch(ctx, e)
	if err != nil {
		return "", fmt.Errorf("%w: ref %q: %v", ErrUnavailable, ref, err)
	}
	v.store(ref, val, lease)
	v.audit(ctx, ref, e.Path, ActionResolve)
	return val, nil
}

// fetch — одно чтение Vault: dynamic (username/password в шаблон) или
// kv-v2 (ключ в data.data, с откатом на плоский ответ kv-v1).
func (v *Vault) fetch(ctx context.Context, e Entry) (string, leaseMeta, error) {
	sec, err := v.client.Logical().ReadWithContext(ctx, e.Path)
	if err != nil {
		return "", leaseMeta{}, err
	}
	if sec == nil {
		return "", leaseMeta{}, fmt.Errorf("путь %s: пустой ответ (нет секрета или нет доступа)", e.Path)
	}
	if e.DSNTemplate != "" {
		user, _ := sec.Data["username"].(string)
		pass, _ := sec.Data["password"].(string)
		if user == "" || pass == "" {
			return "", leaseMeta{}, fmt.Errorf("путь %s: нет username/password (ожидалась dynamic-лиза)", e.Path)
		}
		val := strings.NewReplacer(
			"{{username}}", user,
			"{{password}}", pass,
		).Replace(e.DSNTemplate)
		d := time.Duration(sec.LeaseDuration) * time.Second
		if d <= 0 {
			d = defaultLease
		}
		return val, leaseMeta{id: sec.LeaseID, renewable: sec.Renewable, duration: d}, nil
	}
	data, ok := sec.Data["data"].(map[string]any) // kv-v2
	if !ok {
		data = sec.Data // kv-v1 и прочие плоские ответы
	}
	val, _ := data[e.Key].(string)
	if val == "" {
		return "", leaseMeta{}, fmt.Errorf("путь %s: ключ %q пуст или отсутствует", e.Path, e.Key)
	}
	return val, leaseMeta{}, nil
}

// store — закэшировать лизу и (пере)запустить продление.
func (v *Vault) store(ref, val string, lease leaseMeta) {
	v.mu.Lock()
	if stop, ok := v.cancel[ref]; ok {
		stop()
		delete(v.cancel, ref)
	}
	exp := v.now().Add(lease.duration)
	v.cache[ref] = cacheEntry{value: val, leaseID: lease.id, expiresAt: exp}
	if lease.id != "" && lease.renewable {
		renewCtx, cancel := context.WithCancel(context.Background())
		v.cancel[ref] = cancel
		v.wg.Add(1)
		go v.renewLoop(renewCtx, ref, lease)
	}
	v.mu.Unlock()
}

// renewLoop — фоновое продление лизы до отзыва/истечения/закрытия
// (blueprint п. 12.1, п. 14.2: фоновые задачи — actor scheduler у хука).
// Продление — в середине срока; 403 (отзыв) сбрасывает кэш сразу, иная
// ошибка оставляет кэш до истечения (fail-safe, дальше Resolve возьмёт
// новый секрет — прозрачный реконнект).
func (v *Vault) renewLoop(ctx context.Context, ref string, lease leaseMeta) {
	defer v.wg.Done()
	d := lease.duration
	for {
		timer := d / 2
		if timer < time.Second {
			timer = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-v.ctx.Done():
			return
		case <-time.After(timer):
		}
		resp, err := v.client.Logical().WriteWithContext(ctx, renewPath+lease.id,
			map[string]any{"increment": int(d.Round(time.Second).Seconds())})
		if err != nil {
			var re *vaultapi.ResponseError
			if errors.As(err, &re) && re.StatusCode == 403 {
				v.invalidate(ref)
				v.audit(ctx, ref, v.pathOf(ref), ActionRevoked)
				return
			}
			v.audit(ctx, ref, v.pathOf(ref), ActionRenewFailed)
			return
		}
		if resp == nil || resp.LeaseID == "" {
			v.audit(ctx, ref, v.pathOf(ref), ActionRenewFailed)
			return
		}
		d = time.Duration(resp.LeaseDuration) * time.Second
		if d <= 0 {
			d = defaultLease
		}
		v.extend(ref, v.now().Add(d))
		v.audit(ctx, ref, v.pathOf(ref), ActionRenew)
	}
}

// invalidate — сброс кэша ref (лиза отозвана: кэш недействителен сразу).
func (v *Vault) invalidate(ref string) {
	v.mu.Lock()
	delete(v.cache, ref)
	v.mu.Unlock()
}

// extend — продление expiresAt кэшированной лизы.
func (v *Vault) extend(ref string, exp time.Time) {
	v.mu.Lock()
	if c, ok := v.cache[ref]; ok {
		c.expiresAt = exp
		v.cache[ref] = c
	}
	v.mu.Unlock()
}

func (v *Vault) pathOf(ref string) string {
	if e, ok := v.cfg.Secrets[ref]; ok {
		return e.Path
	}
	return ""
}

func (v *Vault) audit(ctx context.Context, ref, path, action string) {
	if v.cfg.Audit != nil {
		v.cfg.Audit(ctx, ref, path, action)
	}
}

// Close — остановка renewer'ов и освобождение клиента. Idempotent.
func (v *Vault) Close() error {
	v.stop()
	v.mu.Lock()
	for ref, cancel := range v.cancel {
		cancel()
		delete(v.cancel, ref)
	}
	v.mu.Unlock()
	v.wg.Wait()
	return nil
}
