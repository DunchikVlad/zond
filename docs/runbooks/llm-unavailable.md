# Runbook: LLM unavailable / degraded

## 1. Назначение
Этот runbook используется при недоступности или деградации LLM endpoint.

Сценарии:
- массовые `llm_unavailable`;
- резкий рост retry;
- невалидные ответы модели;
- timeouts;
- превышение бюджета из-за повторов или деградации.

## 2. Симптомы
- рост `llm_unavailable` в logs / UI / audit;
- увеличение latency LLM;
- скачок доли `pending`;
- рост количества repair-retry;
- scan чаще заканчивается `partial` или `budget_exceeded`;
- отсутствие новых валидных verdict после LLM stage.

## 3. Возможные причины
- внешний LLM endpoint недоступен;
- локальный LLM перегружен;
- сетевой сбой / DNS / TLS issue;
- rate limit со стороны провайдера;
- неверный API key / secret resolution issue;
- prompt/schema drift -> ответы не проходят валидацию;
- egress policy блокирует endpoint;
- budget / semaphore saturation.

## 4. Быстрая диагностика
Проверить:
1. доступность endpoint;
2. коды HTTP-ответов;
3. долю timeout / retry;
4. валидность JSON-schema response;
5. конфигурацию агента в `detectors.yaml`;
6. секреты / resolver path;
7. egress allowlist;
8. наличие недавних изменений prompt / detectors / model.

Команды / точки наблюдения:
- `agent-check`
- operational logs
- `agent_calls`
- audit events по агентам
- config version / prompt version

## 5. Пошаговые действия

### Шаг 1 — подтвердить характер проблемы
Определить:
- endpoint полностью недоступен;
- endpoint отвечает медленно;
- endpoint отвечает невалидно;
- проблема только у одной модели/одного агента;
- проблема началась после изменения конфигурации.

### Шаг 2 — локализовать область влияния
Проверить:
- затронуты все scans или только один source;
- затронут основной агент или только escalation/verifier;
- растёт ли доля `pending`;
- продолжают ли работать слои 0/1 без деградации.

### Шаг 3 — проверить конфигурацию и секреты
Проверить:
- `endpoint`
- `model`
- `timeout_s`
- `max_retries`
- `confidence_band`
- secret resolution (`ENV` / `Vault`)
- не было ли недавнего hot-reload `detectors.yaml`

### Шаг 4 — выбрать режим деградации
В зависимости от ситуации:
- временно переключить на локальный endpoint;
- отключить внешний агент в безопасном режиме;
- продолжать scan с `UNKNOWN + pending` там, где это соответствует blueprint;
- временно снизить нагрузку / concurrency;
- остановить scan, если риск бюджета или качества неприемлем.

### Шаг 5 — зафиксировать инцидент
Обязательно сохранить:
- период деградации,
- затронутые scan id,
- затронутые agent ids,
- version tuple (`prompt_version`, `detectors_version`, binary version),
- примеры ошибок без raw data.

## 6. Ожидаемый результат
После выполнения runbook должно быть понятно:
- проблема в endpoint, конфиге, секрете, egress policy или schema drift;
- можно ли безопасно продолжать scan;
- нужно ли переключение на fallback / local-only режим;
- нужен ли rollback конфигурации.

## 7. Если не помогло
Эскалировать с приложением:
- `agent_id`
- `model`
- endpoint
- период ошибки
- sample HTTP statuses / timeout types
- `prompt_version`
- `detectors_version`
- результаты `agent-check`
- число affected scans

## 8. Ограничения и меры предосторожности
Нельзя:
- отключать masking ради отладки;
- логировать тела raw-запросов;
- подменять агент на другой без документирования;
- продолжать массовый scan при неконтролируемом росте бюджета;
- менять schema/prompt без фиксации версии.

## 9. Связанные разделы документации
- `blueprint.md`:
  - п. 5.3 — контракт агента
  - п. 6 — ошибки, ретраи, таймауты
  - п. 7 — каскад анализа и ансамбль
  - п. 10 — Agent Proxy
  - п. 17 — метрики и инструментация
  - п. 19 — риски R4, R5, R6, R10
- `architecture.md`:
  - п. 5.1 — Agent Proxy
  - п. 6 — процессная модель и конкурентность
  - п. 10 — cross-cutting concerns
