// Тесты per-profile сэмплирования (S9-6): quick/deep переопределяют default.
package config

import (
	"testing"
)

func TestSampleForProfile(t *testing.T) {
	base := SampleConfig{
		Mode: "percent", Value: 5, MinRows: 100, MaxRows: 20000,
		MaxStringChars: 200, DedupValues: true,
	}
	quick := SampleConfig{
		Mode: "percent", Value: 1, MinRows: 50, MaxRows: 5000,
		MaxStringChars: 100, DedupValues: true,
	}
	deep := SampleConfig{
		Mode: "percent", Value: 10, MinRows: 200, MaxRows: 50000,
		MaxStringChars: 500, DedupValues: true,
	}

	tests := []struct {
		name     string
		profile  string
		wantMode string
		wantVal  float64
		wantMax  int64
	}{
		{"custom (default)", "custom", "percent", 5, 20000},
		{"quick override", "quick", "percent", 1, 5000},
		{"deep override", "deep", "percent", 10, 50000},
		{"unknown → default", "unknown", "percent", 5, 20000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := ScanConfig{Profile: tt.profile, Sample: base, Quick: quick, Deep: deep}
			got := SampleForProfile(sc)
			if got.Mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", got.Mode, tt.wantMode)
			}
			if got.Value != tt.wantVal {
				t.Errorf("value = %v, want %v", got.Value, tt.wantVal)
			}
			if got.MaxRows != tt.wantMax {
				t.Errorf("max_rows = %d, want %d", got.MaxRows, tt.wantMax)
			}
		})
	}
}

func TestSampleForProfilePartialOverride(t *testing.T) {
	base := SampleConfig{Mode: "percent", Value: 5, MinRows: 100, MaxRows: 20000, MaxStringChars: 200}
	// quick переопределяет только value и max_rows
	quick := SampleConfig{Value: 1, MaxRows: 5000}

	sc := ScanConfig{Profile: "quick", Sample: base, Quick: quick}
	got := SampleForProfile(sc)
	if got.Value != 1 {
		t.Errorf("value = %v, want 1", got.Value)
	}
	if got.MaxRows != 5000 {
		t.Errorf("max_rows = %d, want 5000", got.MaxRows)
	}
	// Наследованные поля
	if got.Mode != "percent" {
		t.Errorf("mode = %q, want percent", got.Mode)
	}
	if got.MinRows != 100 {
		t.Errorf("min_rows = %d, want 100", got.MinRows)
	}
}

func TestValidatePerProfile(t *testing.T) {
	// Валидный: quick с корректным mode
	d := &Detectors{
		Version: "1",
		Scan: ScanConfig{
			Profile: "quick",
			Sample:  SampleConfig{Mode: "percent", Value: 5, MaxRows: 20000},
			Quick:   SampleConfig{Mode: "rows", Value: 100},
		},
		Ensemble: EnsembleConfig{TauAccept: 0.8, TauReview: 0.5, Weights: map[string]float64{"meta": 1}},
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Невалидный: quick с плохим mode
	d.Scan.Quick.Mode = "bad"
	if err := d.Validate(); err == nil {
		t.Fatal("ожидалась ошибка: bad mode")
	}
}
