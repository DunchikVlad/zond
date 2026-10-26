package drift

import (
	"testing"

	"github.com/DunchikVlad/zond/internal/verdict"
)

func TestCompareQualifiedTablesIndependently(t *testing.T) {
	base := []verdict.Verdict{
		v("s1", "sales.users", "email", "EMAIL", 0.9),
		v("s1", "archive.users", "email", "EMAIL", 0.9),
	}
	curr := []verdict.Verdict{
		v("s2", "sales.users", "email", "EMAIL", 0.9),
		v("s2", "archive.users", "email", "UNKNOWN", 0.9),
	}
	rep := Compare("s1", base, "s2", curr)
	if len(rep.Added) != 0 || len(rep.Removed) != 0 || len(rep.Changed) != 1 || rep.Changed[0].Table != "archive.users" {
		t.Fatalf("дрейф qualified tables: %+v", rep)
	}
}
