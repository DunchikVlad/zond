package connector

import "testing"

func TestTableRefQualifiedName(t *testing.T) {
	cases := []struct {
		ref  TableRef
		want string
	}{
		{TableRef{Schema: "sales", Name: "users"}, "sales.users"},
		{TableRef{Schema: "archive", Name: "users"}, "archive.users"},
		{TableRef{Schema: "a.b", Name: "c"}, `a\.b.c`},
		{TableRef{Schema: "a", Name: `b\c`}, `a.b\\c`},
	}
	for _, tc := range cases {
		if got := tc.ref.QualifiedName(); got != tc.want {
			t.Errorf("QualifiedName(%+v)=%q, ожидалось %q", tc.ref, got, tc.want)
		}
	}
}
