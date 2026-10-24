package audit

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// SIEM-sink (blueprint п. 14.2, ADR-0013, S8-3): внешняя доставка
// аудит-событий. «Потеря событий недопустима» обеспечена по построению:
// очередь — сам append-only журнал audit_log; воркер держит закладку
// (audit_sink_state.last_seq, миграция 0009) и двигает её только за
// подтверждённо доставленное событие, строго в порядке цепочки. При
// недоступности sink закладка не двигается — повторная отправка с
// backoff'ом (воркер разводит попытки во времени; serve гоняет Pump по
// тикеру). Порядок сохраняется: SIEM может сверять hash-chain напрямую.
//
// Fail-closed по п. 14.2: недоступный sink не роняет запись аудита —
// журнал локален и append-only, доставка догонит по восстановлении.
//
// Зависимости: пакет audit не тянет config — протокол/адрес задаются
// зеркальным SinkConfig (конвертация из connections.yaml — в cmd, п. 14.2).

// SinkKind — тип SIEM-sink (п. 14.2): json-tcp (NDJSON поверх TCP) или
// syslog (CEF-подобная строка, UDP/TCP; по умолчанию UDP).
type SinkKind string

const (
	SinkJSONTCP SinkKind = "json-tcp"
	SinkSyslog  SinkKind = "syslog"
)

// SinkConfig — адрес sink для воркера (конверт из config.SinkConfig, cmd).
type SinkConfig struct {
	Kind    SinkKind // json-tcp | syslog
	Address string   // host:port SIEM
	Proto   string   // syslog: udp (default) | tcp
}

// SinkBatch — пакетная доставка: столько записей читает воркер за цикл.
const SinkBatch = 128

// Sink — воркер доставки аудит-событий во внешний SIEM (п. 14.2).
// Живёт в процессе serve (sink — опция инсталляции). Nil-safe: нулевой
// приёмник = sink выключен (только локальный журнал).
type Sink struct {
	db  *sql.DB
	cfg SinkConfig
	log *slog.Logger

	// nowFn — подменяемые часы (тесты).
	nowFn func() time.Time
	// dial — подменяемый коннект (тесты: in-memory listener).
	dial func(network, address string) (net.Conn, error)
}

// NewSink собирает воркер по конфигу (nil db отклоняется — журнал в БД).
// Пустой конфиг = nil (sink выключен; валидация схемы — при загрузке
// connections.yaml, здесь не повторяем).
func NewSink(db *sql.DB, cfg SinkConfig, log *slog.Logger) *Sink {
	if db == nil || cfg.Kind == "" {
		return nil
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Sink{db: db, cfg: cfg, log: log, nowFn: time.Now,
		dial: func(network, address string) (net.Conn, error) {
			return net.DialTimeout(network, address, 3*time.Second)
		}}
}

// Enabled — sink настроен (non-nil приёмник).
func (s *Sink) Enabled() bool { return s != nil }

// Kind — тип sink из конфига (логи/doctor).
func (s *Sink) Kind() SinkKind {
	if s == nil {
		return ""
	}
	return s.cfg.Kind
}

// Pump — один цикл доставки: пакет событий за закладкой (≤ SinkBatch),
// строго в порядке цепочки. Возвращает число доставленных. Первая
// недоставленная запись останавливает цикл (порядок — гарантия сверки
// hash-chain на стороне SIEM) и отражается в закладке (last_error);
// закладка не двигается за неё — повтор на следующем Pump (потеря
// недопустима, п. 14.2). Операции с БД — вне ctx цикла (доставка не
// умирает с отменой скана-родителя).
func (s *Sink) Pump(ctx context.Context) (int, error) {
	if s == nil {
		return 0, nil
	}
	bg := context.Background()
	last, err := SinkLastSeq(bg, s.db)
	if err != nil {
		return 0, fmt.Errorf("sink: закладка: %w", err)
	}
	pending, err := SinkEntries(bg, s.db, last, SinkBatch)
	if err != nil {
		return 0, fmt.Errorf("sink: выборка журнала: %w", err)
	}
	delivered := 0
	for _, e := range pending {
		if ctx.Err() != nil {
			break
		}
		if derr := s.deliver(e); derr != nil {
			_ = SinkAdvance(bg, s.db, last, derr.Error(), s.nowFn())
			s.log.Warn("sink: доставка отложена — закладка на месте",
				"seq", e.Seq, "last_seq", last, "error", derr)
			break
		}
		last = e.Seq
		if err := SinkAdvance(bg, s.db, last, "", s.nowFn()); err != nil {
			s.log.Error("sink: продвижение закладки", "seq", last, "error", err)
			break
		}
		delivered++
	}
	return delivered, nil
}

// deliver — одна запись в sink по протоколу конфига (п. 14.2: каноническая
// форма на проводе).
func (s *Sink) deliver(e SinkEntry) error {
	network := "tcp"
	if s.cfg.Kind == SinkSyslog {
		network = s.cfg.Proto
		if network == "" {
			network = "udp"
		}
	} else if s.cfg.Kind != SinkJSONTCP {
		return fmt.Errorf("sink: неизвестный kind %q", s.cfg.Kind)
	}
	payload := e.Canonical // NDJSON: canonical уже с терминатором "\n"
	if s.cfg.Kind == SinkSyslog {
		payload = cefLine(e)
	}
	conn, err := s.dial(network, s.cfg.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(s.nowFn().Add(5 * time.Second)); err != nil {
		return err
	}
	_, err = fmt.Fprint(conn, payload)
	return err
}

// cefLine — строка syslog/CEF: seq как номер записи, msg — каноническая
// форма события (сверка hash-chain на стороне SIEM, п. 14.2).
func cefLine(e SinkEntry) string {
	return fmt.Sprintf("CEF:0|DunchikVlad|zond|1|%d|audit|%d|msg=%s\n",
		e.Seq, e.Seq, e.Canonical)
}
