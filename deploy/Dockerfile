# Образ zond (blueprint п. 15 «Харденинг контейнера»): scratch без шелла,
# non-root (UID 65534), read-only root FS совместим (единственная запись —
# смонтированный том /data с SQLite). Секреты — только env/Vault, никогда
# в слоях образа. Сборка: docker build -f deploy/Dockerfile .

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
      -o /out/zond ./cmd/zond
# /data в scratch-образе: каталог с владельцем 65534 — named volume
# docker инициализирует содержимым/владельцем образа (иначе volume от root
# и SQLite под nobody не открывается: "unable to open database file (14)";
# найдено первым прогоном smoke на стенде, 2026-10-24).
RUN mkdir -p /data && chown 65534:65534 /data

FROM scratch
COPY --from=build /out/zond /zond
# CA — для https-эндпоинтов (LLM/Vault) при включённых соответствующих функциях.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65534:65534 /data /data
USER 65534:65534
ENTRYPOINT ["/zond"]
