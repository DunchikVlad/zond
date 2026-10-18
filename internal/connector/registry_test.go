package connector

import (
	"errors"
	"reflect"
	"testing"
)

func testFactory(dsn string) (Connector, error) { return nil, errors.New("stub") }

func TestRegistryRegisterLookup(t *testing.T) {
	if err := Register("reg-test-a", testFactory); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := Register("reg-test-b", testFactory); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := Register("reg-test-a", testFactory); err == nil {
		t.Fatal("дубль типа должен давать ошибку")
	}
	if err := Register("", testFactory); err == nil {
		t.Fatal("пустой тип должен давать ошибку")
	}
	var nilFactory Factory
	if err := Register("reg-test-nil", nilFactory); err == nil {
		t.Fatal("nil factory должен давать ошибку")
	}

	f, ok := Lookup("reg-test-a")
	if !ok || reflect.ValueOf(f).Pointer() != reflect.ValueOf(testFactory).Pointer() {
		t.Fatal("Lookup не вернул зарегистрированный конструктор")
	}
	if _, ok := Lookup("reg-test-absent"); ok {
		t.Fatal("Lookup вернул конструктор для незарегистрированного типа")
	}

	got := Types()
	want := []string{"reg-test-a", "reg-test-b"}
	if !reflect.DeepEqual(got[:2], want) {
		t.Fatalf("Types() = %v, префикс ожидался %v (реестр глобальный)", got, want)
	}
}
