BINARY  := zond
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.Version=$(VERSION) -X main.Commit=$(COMMIT)

.PHONY: build test test-race vet fmt lint cover config-check ci eval clean

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

clean:
	rm -rf bin coverage.out coverage.html
