package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/DunchikVlad/zond/internal/config"
	"github.com/DunchikVlad/zond/internal/connector"
	"github.com/DunchikVlad/zond/internal/scanengine"
	"github.com/DunchikVlad/zond/internal/verdict/store"
)

func TestRunnerResumeProvenance(t *testing.T) {
	release := make(chan struct{})
	close(release)
	if err := connector.Register("test-resume", func(string) (connector.Connector, error) {
		return &gateConn{release: release}, nil
	}); err != nil {
		t.Fatal(err)
	}
	b := &config.Bundle{
		Connections: &config.Connections{Version: "1", Sources: []config.Source{{Name: "db", Type: "test-resume", DSN: "test://x"}}},
		Detectors:   &config.Detectors{Version: "1"},
		Taxonomy:    &config.Taxonomy{Version: "1"},
	}
	st, err := store.Open(t.TempDir() + "/resume.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := newEngineRunner(b, st, slog.New(slog.DiscardHandler), false, nil)
	fingerprint, err := config.ScanFingerprint(b, &b.Connections.Sources[0], "deep", false)
	if err != nil {
		t.Fatal(err)
	}
	prev := &store.Scan{
		ID: "old", SourceName: "db", Profile: "deep", Status: "partial", StartedAt: time.Now().UTC(),
		ConfigFingerprint: fingerprint, TaxonomyVersion: "1", DetectorsVersion: "1", BinaryVersion: Version,
	}
	if err := st.SaveScan(context.Background(), prev); err != nil {
		t.Fatal(err)
	}
	newID, err := r.Resume(prev.ID, "test")
	if err != nil {
		t.Fatalf("совместимый resume: %v", err)
	}
	if newID == "" || newID == prev.ID {
		t.Fatalf("новый ID: %q", newID)
	}

	bad := &store.Scan{ID: "bad", SourceName: "db", Profile: "deep", Status: "partial", StartedAt: time.Now().UTC(),
		ConfigFingerprint: fingerprint, TaxonomyVersion: "old", DetectorsVersion: "1", BinaryVersion: "old"}
	if err := st.SaveScan(context.Background(), bad); err != nil {
		t.Fatal(err)
	}
	_, err = r.Resume(bad.ID, "test")
	var compat *scanengine.ResumeCompatibilityError
	if !errors.As(err, &compat) || len(compat.Mismatches) != 2 {
		t.Fatalf("ожидались два mismatch до подключения: %v", err)
	}
	if _, err := r.st.GetScan(context.Background(), "bad"); err != nil {
		t.Fatal(err)
	}
}
