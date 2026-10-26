package config

import "testing"

func TestScanFingerprint(t *testing.T) {
	b := &Bundle{
		Detectors: &Detectors{Version: "1", Ensemble: EnsembleConfig{Weights: map[string]float64{"rules": 1}}},
		Taxonomy:  &Taxonomy{Version: "1"},
	}
	src := &Source{Name: "db", Type: "clickhouse", DSN: "clickhouse://user:old@localhost:9000/default"}
	first, err := ScanFingerprint(b, src, "deep", false)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ScanFingerprint(b, src, "deep", false)
	if first != again {
		t.Fatal("fingerprint недетерминирован")
	}
	src.DSN = "clickhouse://user:new@localhost:9000/default"
	rotated, _ := ScanFingerprint(b, src, "deep", false)
	if first != rotated {
		t.Fatal("ротация пароля не должна менять fingerprint")
	}
	b.Detectors.Ensemble.Weights["rules"] = 2
	changed, _ := ScanFingerprint(b, src, "deep", false)
	if first == changed {
		t.Fatal("изменение детекторов не отражено в fingerprint")
	}
}
