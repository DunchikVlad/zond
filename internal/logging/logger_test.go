package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestCorrelationIDInJSON(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "info")
	ctx := WithCorrelation(context.Background(), "cid-123")
	log.InfoContext(ctx, "тест", "component", "x")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("невалидный JSON: %v (%q)", err, buf.String())
	}
	if rec["correlation_id"] != "cid-123" {
		t.Fatalf("correlation_id отсутствует: %v", rec)
	}
	if rec["level"] != "INFO" || rec["msg"] != "тест" {
		t.Fatalf("неожиданные поля: %v", rec)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "warn")
	log.InfoContext(context.Background(), "не должно попасть")
	log.DebugContext(context.Background(), "тоже нет")
	if buf.Len() != 0 {
		t.Fatalf("запись ниже уровня прошла: %s", buf.String())
	}
	log.ErrorContext(context.Background(), "должно попасть")
	if buf.Len() == 0 {
		t.Fatal("error не записан при уровне warn")
	}
}

func TestNoCorrelationNoField(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "info")
	log.InfoContext(context.Background(), "plain")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("невалидный JSON: %v", err)
	}
	if _, ok := rec["correlation_id"]; ok {
		t.Fatal("correlation_id появился без WithCorrelation")
	}
}

func TestDefaultLevelInfo(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "")
	log.InfoContext(context.Background(), "ok")
	if buf.Len() == 0 {
		t.Fatal("по умолчанию уровень info")
	}
}
