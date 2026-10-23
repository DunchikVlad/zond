# Runbook: демо-контур Vault для zond (ADR-0012)

## 1. Назначение
Подъём локального dev-контура HashiCorp Vault и проверка резолвера
секретов zond (`internal/secrets`, blueprint п. 12.1): kv-v2 и dynamic
leases (database secrets engine).

Внимание: контур — dev-режим Vault (root token из env, без TLS, без
seal). Только для локальной демонстрации и проверок. Прод — по
эксплуатационным требованиям п. 15 (TLS, seal, свои политики).

## 2. Подъём

```bash
docker compose -f deploy/docker-compose.vault.yml up -d
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=zond-dev-root-token   # VAULT_DEV_ROOT_TOKEN_ID по умолчанию
vault status
```

## 3. Секреты

### 3.1 kv-v2 (готовый URI под ключом)

```bash
vault secrets enable -path=kv kv-v2
vault kv put kv/zond/mongo-prod uri="mongodb://test:test@192.168.31.119:27017/testdb"
# чтение API-эквивалентно пути kv/data/zond/mongo-prod
```

### 3.2 Dynamic leases (database secrets engine)

Нужна БД и учётка администратора Vault в ней. Пример для MongoDB
(тестовый стенд 192.168.31.119; замените на свой хост/учётку):

```bash
vault secrets enable database
vault write database/config/mongo \
  plugin_name=mongodb-database-plugin \
  connection_url="mongodb://{{username}}:{{password}}@192.168.31.119:27017/admin" \
  username="vault_admin" password="<пароль администратора>" \
  allowed_roles="zond-readonly"
vault write database/roles/zond-readonly db_name=mongo \
  creation_statements='{"db":"testdb","roles":[{"role":"read","db":"testdb"}]}' \
  default_ttl="1h" max_ttl="24h"
# лизы выдаются по пути database/creds/zond-readonly
```

## 4. Конфигурация zond

В `connections.yaml` (фрагмент; полный пример — комментарий в
configs/connections.yaml):

```yaml
sources:
  - name: mongo-prod
    type: mongodb
    ref: mongo-prod            # вместо dsn/uri — секрет из Vault (п. 12.1)
vault:
  enabled: true
  address: "http://127.0.0.1:8200"
  auth: {method: token, token_env: VAULT_TOKEN}   # dev; prod — kubernetes
  secrets:
    - {ref: mongo-prod, path: kv/data/zond/mongo-prod, key: uri}
    - {ref: mongo-demo, path: database/creds/zond-readonly,
       dsn_template: "mongodb://{{username}}:{{password}}@192.168.31.119:27017/testdb"}
```

(источник `mongo-demo` добавьте аналогично с `ref: mongo-demo`.)

## 5. Проверка

```bash
zond config validate
zond doctor -online        # строки vault (аутентификация) и vault.read
zond scan -source mongo-prod
zond audit export -category secrets   # resolve без значений (п. 14.2)
```

Ожидаемо в doctor (online): `vault OK — аутентификация method=token`,
`vault.read mongo-prod OK — секрет читается (kv-v2)`. Для dynamic:
«dynamic lease»; лиза продлевается фоновой горутиной, события —
`lease_renew` в аудите (actor scheduler).

## 6. Деградация и отказ (R11)

- Vault недоступен при старте источника: источник `failed` с причиной
  `vault_unavailable` (остальные источники сканируются). Валидная лиза
  из кэша используется до истечения; дальше — повторный резолв.
- Отозванная лиза (403 на renew) сбрасывает кэш сразу; следующий
  коннект прозрачно возьмёт новый секрет.
- Диагностика: `zond doctor -online` (vault/vault.read), лог serve,
  аудит `-category secrets`.
- Возврат к ENV-режиму: `vault.enabled=false` + `dsn`/`uri` в источниках
  (рестарт; п. 12: connections.yaml — только рестарт).

## 7. Связанные разделы документации
- `blueprint.md`: п. 12.1 (Vault), п. 14.2 (аудит), R11 (недоступность)
- `docs/decisions/ADR-impl-stage-7v-vault.md` — решения реализации
- `internal/secrets` — Resolver, кэш лиз, продление
