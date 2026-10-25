# Прогресс: этап 8, инкремент 8-8 — горячая перезагрузка detectors.yaml (ADR-0014)

Дата: 2026-10-25
Исполнитель: агент сессии
Статус: **done** (S8-8, `135a5d4`; ПРОВЕРЕНО НА СТЕНДЕ).
Закрывает объявленный в шапке detectors.yaml долг: «Hot-reload без
рестарта — ADR-0014 (реализация позже, контракт — сейчас)» — для
порогов/весов/лимитов; реестр агентов и taxonomy — по-прежнему рестарт.

## 1. Что сделано

| Чанк | Результат |
|---|---|
| S8-8 | **config.DetectorsEditor** — правка detectors.yaml через yaml.v3 Node: секционные комментарии сохраняются; скаляры пишутся с авто-типизацией (числа не превращаются в `!!str` — scalarAuto); вложенные секции через mappingFindPath (ensemble.weights); валидация — строгий разбор + `Detectors.Validate` (tau_review < tau_accept, profile enum, веса > 0, similarity ∈ (0,1] и пр.) |
| S8-8 | **UI «Настройки»**: форма «Детекторы» — профиль quick/deep/custom, tau_accept/tau_review, веса meta/rules/llm, cluster similarity/max_size, proxy max_concurrent/rate_limit_rps/cost_scan_limit_usd, offline. Реестр агентов и таксономия — просмотр (правка — рестарт; endpoint/egress/промпт-enum безопаснее менять осознанно) |
| S8-8 | **Горячее применение без рестарта**: запись файла (.bak + атомарная замена) → LoadDetectors → atomic swap `bundleHot`; engineRunner получает детекторы через `bundle()` при каждом старте прогона (пороги/веса/лимиты новых прогонов; LLM-композит и дефолтный профиль — тоже свежие). Действующие прогоны завершаются со старыми порогами — осознанно (документировано) |
| S8-8 | Аудит `admin/detectors_update` (значения в деталях, секретов нет — в detectors.yaml их нет по построению) |

## 2. Живой прогон на стенде (.113, сборка 135a5d4)

- GET /settings → 200, форма показывает актуальные tau_review=0.50.
- POST /settings/detectors/save (tau_review=0.45, w_llm=1.35) → 303; в
  файле `llm: 1.35` при сохранённых комментариях; применено без рестарта.
- Откат файла из .bak + рестарт — стенд в исходной конфигурации, health ok.

## 3. Проверки

`make ci`, race (web/config/cmd), `golangci-lint` — 0 issues. Тесты:
DetectorsEditor (round-trip, авто-типизация, вложенные веса, отказы
валидации), web-сценарий (save → apply → аудит; отказ tau_review ≥
tau_accept не пишет файл). Протокол:
`docs/validation/2026-10-25-stage-8-8-detectors-reload.md`.

## 4. Ограничения (явно)

- Профили quick/deep/custom — по-прежнему только имя (единый scan.sample);
  семантическая разница профилей — отдельная задача (п. 5.2).
- taxonomy.yaml — рестарт (промпт-enum, кэш-ключи LLM).
- Реестр агентов — рестарт (egress/endpoint/модель).
