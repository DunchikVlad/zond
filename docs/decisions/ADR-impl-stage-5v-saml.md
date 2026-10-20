# ADR-impl: инкремент 5в-5 — SAML Service Provider (SSO)

Дата: 2026-10-20
Статус: accepted
Связь: ADR-0011, blueprint п. 11.3, п. 14; прогресс —
`2026-10-20-stage-5v-saml-sp.md`; часть 1 —
`ADR-impl-stage-5v-tokens-rbac.md`

## D1. Ключи подписи SP — файлы в конфиге; ephemeral только как bootstrap

**Выбор:** `sp_key_file`/`sp_certificate_file` (PEM) в sso:-блоке
connections.yaml. Не заданы — ephemeral self-signed (RSA 2048, 1 год)
генерируется на старте с warn-логом и аудитом `sso_ephemeral_cert`.

**Обоснование:** п. 11.3 требует файл в конфигурации и процедуру ротации
«добавить новый → раскатить → убрать старый». Полный отказ от ephemeral
ломал бы dev/демо и E2E-тесты (сертификат на каждый прогон). Prod-чек
(sp_certificate_file задан) — в `doctor` (этап 7).

## D2. Refresh метаданных IdP = пересборка middleware

**Выбор:** каждые 24 ч `FetchMetadata` (url/file) → `buildMiddleware` →
`atomic.Pointer` swap. Ошибка — warn + аудит, прежняя версия действует.

**Отклонённая альтернатива:** мутировать `ServiceProvider.IDPMetadata`
под mutex — crewjam читает поле внутри запросов, наружной блокировки нет;
гонка неустранима без форка. Пересборка middleware дёшевa (десятки мс) и
атомарна. П. 11.3 (ротация ключей IdP без рестарта) закрыт.

## D3. SameSite cookie — конфигурируемо, default lax

**Выбор:** `cookie_samesite: lax` (default) | `none`. На https-развёртываниях
`none` + Secure. Tracked-request cookie (InResponseTo) при lax на http-dev
у части браузеров не доедет до POST ACS — задокументировано в конфиге и
validation; prod — https.

**Почему не Always None:** None без Secure браузеры отвергают; Secure на
http-dev (loopback) сломал бы тесты и локальный сценарий.

## D4. SAMLResponse никогда не пишется в аудит/ошибки

Ошибки ACS оборачиваются: аудит `sso_login_failure` получает только
типизированную причину (`InvalidResponseError.PrivateErr`, ≤160 символов).
`Error()` crewjam сам не содержит XML, но внутренние ошибки dsig могли бы
нести фрагменты — обрезка гарантирует отсутствие assertion в логах
(ADR-0010, п. 18.2 минимизация).

## D5. Аудит SSO — best effort, не fail-closed

Отказ записи аудита не отменяет вход/выход (self-DoS); ошибка аудита идёт
в операционный лог, целостность цепочки проверяется `zond audit verify`.
Противопоставление D4 ADR-impl-5а (доменные мутации fail-closed): там
отказ транзакции = отказ действия естественен; здесь действие выполнило
криптографическую валидацию, а аудит — наблюдаемость.

## D6. IdP-initiated SLO — минимальный самостоятельный разбор

crewjam v0.5.1 не поставляет парсер/валидатор LogoutRequest. Реализован
разбор NameID (redirect: base64+flate; POST: base64/XML) + `DeleteBySubject`.
Подпись LogoutRequest не валидируется — риск (поддельный SLO завершает
сессию) зафиксирован в security note; эскалации прав нет. При появлении
валидатора (crewjam/свой через goxmldsig) — включить.
