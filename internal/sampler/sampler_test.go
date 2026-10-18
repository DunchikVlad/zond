package sampler

import (
	"errors"
	"iter"
	"testing"

	"github.com/DunchikVlad/zond/internal/connector"
)

func rowsOf(rows ...connector.Row) iter.Seq2[connector.Row, error] {
	return func(yield func(connector.Row, error) bool) {
		for _, r := range rows {
			if !yield(r, nil) {
				return
			}
		}
	}
}

func TestBuildDedupAndTruncate(t *testing.T) {
	rows := rowsOf(
		connector.Row{"email": "a@b.co"},
		connector.Row{"email": "a@b.co"},
		connector.Row{"email": "x@y.io"},
		connector.Row{"email": nil},
		connector.Row{"other": "ignored"},
	)
	p, err := Build(rows, "email", Options{Dedup: true, MaxStringChars: 5})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(p.Values) != 2 {
		t.Fatalf("dedup не сработал: %v", p.Values)
	}
	if p.Values[0] != "a@b.c" || p.Values[1] != "x@y.i" {
		t.Fatalf("truncate неверен: %v", p.Values)
	}
	if p.Total != 5 || p.Nulls != 2 {
		t.Fatalf("счётчики: total=%d nulls=%d", p.Total, p.Nulls)
	}
}

func TestBuildMaxRows(t *testing.T) {
	rows := rowsOf(
		connector.Row{"c": "1"}, connector.Row{"c": "2"}, connector.Row{"c": "3"},
	)
	p, err := Build(rows, "c", Options{MaxRows: 2})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(p.Values) != 2 || p.Total != 2 {
		t.Fatalf("max rows не сработал: %v total=%d", p.Values, p.Total)
	}
}

func TestBuildStreamError(t *testing.T) {
	sentinel := errors.New("stream boom")
	seq := func(yield func(connector.Row, error) bool) {
		yield(connector.Row{"c": "1"}, nil)
		yield(nil, sentinel)
	}
	p, err := Build(seq, "c", Options{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("ошибка стрима не проброшена: %v", err)
	}
	if len(p.Values) != 1 {
		t.Fatalf("полученные значения потеряны: %v", p.Values)
	}
}

func TestStringify(t *testing.T) {
	ok := []struct {
		v    any
		want string
	}{
		{" s ", "s"},
		{[]byte("b"), "b"},
		{true, "true"},
		{42, "42"},
		{int64(-7), "-7"},
		{1.5, "1.5"},
	}
	for _, c := range ok {
		s, good := Stringify(c.v)
		if !good || s != c.want {
			t.Errorf("Stringify(%v) = %q,%v; ожидалось %q", c.v, s, good, c.want)
		}
	}
	for _, v := range []any{nil, struct{}{}, []int{1}, map[string]int{}} {
		if s, good := Stringify(v); good || s != "" {
			t.Errorf("Stringify(%v) должен быть !ok", v)
		}
	}
}
