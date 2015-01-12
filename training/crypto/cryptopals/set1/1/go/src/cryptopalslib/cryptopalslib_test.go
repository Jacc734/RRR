package cryptopalslib

import (
	"reflect" // used to compare "complex" types (slices)
	"testing"
)

//****
// TESTS FOR TYPE CONVERSION FUNCTIONS
//************************************

func TestBytesToString(t *testing.T) {
	t.Log("Executing TestBytesToString...")

	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("Hello, world"), "Hello, world"},
	}
	for _, c := range cases {
		got := BytesToString(c.in)
		if got != c.want {
			t.Errorf("BytesToString(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStringToBytes(t *testing.T) {
	t.Log("Executing TestStringToBytes...")

	cases := []struct {
		in   string
		want []byte
	}{
		{"Hello, world", []byte("Hello, world")},
	}
	for _, c := range cases {
		got := StringToBytes(c.in)
		if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("StringToBytes(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}
