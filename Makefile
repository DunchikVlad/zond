BINARY  := zond
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)

.PHONY: build test test-race vet fmt lint cover config-check ci eval bench clean

build: ## Сборка bin/zond с версией из git
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/zond

test: ## Unit-тесты
	go test ./...

test-race: ## Тесты с race-detector
	go test -race ./...

vet: ## go vet
	go vet ./...

fmt: ## Проверка форматирования (gofmt)
	gofmt -l .

lint: ## golangci-lint (требует установленный бинарник)
	golangci-lint run

cover: ## Покрытие по пакетам
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# Конфиги валидируются с фиктивными ENV (configs/ci.env) — не секреты.
config-check: build
	set -a && . ./configs/ci.env && set +a && ./bin/$(BINARY) config validate

ci: fmt vet build test ## Локальный прогон CI-ворот

# Отчёт F1/$ по эталонному датасету (слоёв 0+1, детерминировано; датасет
# закоммичен, регенерация — `go run ./cmd/eval generate`, меняет manifest).
# LLM-слой: go run ./cmd/eval run -llm (см. usage подкоманды).
eval: ## Отчёт F1 и $/1000 колонок по датасету (evals/reports/report.json)
	go run ./cmd/eval run

# ---------------------------------------------------------------------------
# Нагрузочный тест слоя 1 (blueprint п. 16.8): 1M детерминированных
# синтетических значений через rules.Analyze; NFR п. 18 — ≥100 000
# значений/мин на ядро. Код выхода 1 при провале (CI-гейт, ci.yml).
# Отчёт — evals/reports/bench.json (в git не коммитится, .gitignore).
# ---------------------------------------------------------------------------
bench: ## Нагрузочный тест слоя 1: 1M значений, NFR п. 18 (≥100k знач/мин на ядро)
	go run ./cmd/eval bench

# ---------------------------------------------------------------------------
# Релиз (S7г, blueprint п. 15/18): кросс-сборка, checksums, SBOM (syft),
# подпись (cosign, keyless). dist/ — не коммитится (.gitignore).
# ---------------------------------------------------------------------------
DIST      := dist
PLATFORMS := linux/amd64 linux/arm64 windows/amd64

.PHONY: dist checksums sbom sign release
dist: ## Кросс-сборка релизных бинарей (п. 18: linux/amd64, linux/arm64, windows/amd64)
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  goos=$$(echo $$p | cut -d/ -f1); goarch=$$(echo $$p | cut -d/ -f2); \
	  out=$(DIST)/zond-$(VERSION)-$$goos-$$goarch; \
	  if [ "$$goos" = windows ]; then out=$$out.exe; fi; \
	  echo "build $$goos/$$goarch -> $$out"; \
	  GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/zond; \
	done

checksums: dist ## SHA256SUMS.txt по артефактам dist (п. 15, релизный чеклист)
	cd $(DIST) && sha256sum zond-* > SHA256SUMS.txt && cat SHA256SUMS.txt

sbom: ## SBOM (syft, SPDX-JSON) - requires syft in PATH; in CI see release.yml
	@if command -v syft >/dev/null 2>&1; then \
	  syft dir:. -o spdx-json=$(DIST)/zond-$(VERSION)-sbom.spdx.json; \
	else \
	  echo "syft not found - skipping SBOM (CI: anchore/sbom-action)"; \
	fi

sign: checksums ## cosign (keyless) signature - requires cosign in PATH
	@if command -v cosign >/dev/null 2>&1; then \
	  cd $(DIST) && cosign sign-blob --yes --output-signature zond.sig zond-* SHA256SUMS.txt; \
	else \
	  echo "cosign not found - skipping signature (CI: sigstore/cosign-installer)"; \
	fi

release: checksums sbom sign ## Полный релизный набор (п. 15: бинари + checksums + SBOM + подпись)

# Эталонный контур (blueprint п. 15, DoD п. 22): compose app+ClickHouse+
# MongoDB+seed, разовый quick-скан до первых вердиктов (зелёный smoke =
# код 0 и вердикты в UI на 127.0.0.1:8080). Требует docker.
smoke: ## Подъём smoke-контура и quick-скан до вердиктов (≤15 мин с нуля)
	docker compose -f deploy/docker-compose.yml --profile smoke run --rm --build smoke-scan
	@echo "smoke: скан завершён (код 0) — вердикты в UI:"
	docker compose -f deploy/docker-compose.yml up -d app
	@echo "  http://127.0.0.1:8080  (остановка и очистка: make smoke-clean)"

smoke-clean: ## Остановка и очистка smoke-контура (тома)
	docker compose -f deploy/docker-compose.yml down -v

clean:
	rm -rf bin $(DIST) coverage.out coverage.html
