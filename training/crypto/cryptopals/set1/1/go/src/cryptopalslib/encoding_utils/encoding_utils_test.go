package encoding_utils

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

//****
// TESTS FOR HEX FUNCTIONS
//************************************

func TestHexEncodeStringToString(t *testing.T) {
	t.Log("Executing TestHexEncodeStringToString...")

	cases := []struct {
		in   string
		want string
	}{
		{"Hello, world", "48656c6c6f2c20776f726c64"},
	}
	for _, c := range cases {
		got := HexEncodeStringToString(c.in)
		if got != c.want {
			t.Errorf("HexEncodeStringToString(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHexDecodeStringToString(t *testing.T) {
	t.Log("Executing TestHexDecodeStringToString...")

	cases := []struct {
		in   string
		want string
	}{
		{"48656c6c6f2c20776f726c64", "Hello, world"},
	}
	for _, c := range cases {
		got, err := HexDecodeStringToString(c.in)
		if err != nil {
			t.Error("Test error: ", err)
		} else if got != c.want {
			t.Errorf("HexDecodeStringToString(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHexEncodeByteArrayToString(t *testing.T) {
	t.Log("Executing HexEncodeByteArrayToString...")

	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64},
			"48656c6c6f2c20776f726c64"},
		{[]byte("Hello, world"), "48656c6c6f2c20776f726c64"},
	}
	for _, c := range cases {
		got := HexEncodeByteArrayToString(c.in)
		if got != c.want {
			t.Errorf("HexEncodeByteArrayToString(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHexDecodeByteArrayToByteArray(t *testing.T) {
	t.Log("Executing HexDecodeByteArrayToByteArray")

	cases := []struct {
		in   []byte
		want []byte
	}{
		{[]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
			[]byte("I'm killing your brain like a poisonous mushroom")},
	}
	for _, c := range cases {
		got, err := HexDecodeByteArrayToByteArray(c.in)
		if err != nil {
			t.Error("Test error: ", err)
		} else if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("HexDecodeByteArrayToByteArray(%q) => %x, want %q", c.in, got, c.want)
		}
	}
}

func TestHexDecodeByteArrayToString(t *testing.T) {
	t.Log("Executing HexDecodeByteArrayToString...")

	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x49, 0x27, 0x6d, 0x20, 0x6b, 0x69, 0x6c, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x79},
			"I'm killing y"},
		{[]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64},
			"Hello, world"},
		{[]byte("Hello, world"), "Hello, world"},
		{[]byte{0x41, 0x41, 0x41, 0x42}, "AAAB"},
	}
	for _, c := range cases {
		got, err := HexDecodeByteArrayToString(c.in)
		if err != nil {
			t.Error("Test error: ", err)
		} else if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("HexDecodeByteArrayToString(%q) => %x, want %q", c.in, got, c.want)
		}
	}
}

func TestHexDecodeStringToByteArray(t *testing.T) {
	t.Log("Executing HexDecodeStringToByteArray")

	cases := []struct {
		in   string
		want []byte
	}{
		{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			[]byte("I'm killing your brain like a poisonous mushroom")},
	}
	for _, c := range cases {
		got, err := HexDecodeStringToByteArray(c.in)
		if err != nil {
			t.Error("Test error: ", err)
		} else if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("HexDecodeStringToByteArray(%q) => %x, want %q", c.in, got, c.want)
		}
	}

}

//****
// TESTS FOR BASE64 FUNCTIONS
//***************************

func TestBase64EncodeStringToString(t *testing.T) {
	t.Log("Executing Base64EncodeStringToString...")

	cases := []struct {
		in   string
		want string
	}{
		{"Hello, world", "SGVsbG8sIHdvcmxk"},
		{"Hello, world €", "SGVsbG8sIHdvcmxkIOKCrA=="},
	}
	for _, c := range cases {
		got := Base64EncodeStringToString(c.in)
		if got != c.want {
			t.Errorf("Base64EncodeStringToString(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBase64DecodeStringToString(t *testing.T) {
	t.Log("Executing Base64DecodeStringToString...")

	cases := []struct {
		in   string
		want string
	}{
		{"SGVsbG8sIHdvcmxk", "Hello, world"},
		{"SGVsbG8sIHdvcmxkIOKCrA==", "Hello, world €"},
	}
	for _, c := range cases {
		got, err := Base64DecodeStringToString(c.in)
		if err != nil {
			t.Log("Test error: ", err)
		} else if got != c.want {
			t.Errorf("Base64DecodeStringToString(%q) => %x, want %q", c.in, got, c.want)
		}
	}
}

func TestBase64EncodeByteArrayToString(t *testing.T) {
	t.Log("Executing Base64EncodeByteArrayToString...")

	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64},
			"SGVsbG8sIHdvcmxk"},
		{[]byte("Hello, world"), "SGVsbG8sIHdvcmxk"},
	}
	for _, c := range cases {
		got := Base64EncodeByteArrayToString(c.in)
		if got != c.want {
			t.Errorf("Base64EncodeByteArrayToString(%q) => %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBase64DecodeByteArrayToString(t *testing.T) {
	t.Log("Executing Base64DecodeByteArrayToString...")

	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("SGVsbG8sIHdvcmxk"), "Hello, world"},
		{[]byte("SGVsbG8sIHdvcmxkIOKCrA=="), "Hello, world €"},
	}
	for _, c := range cases {
		got, err := Base64DecodeByteArrayToString(c.in)
		if err != nil {
			t.Log("Test error: ", err)
		} else if got != c.want {
			t.Errorf("Base64DecodeByteArrayToString(%q) => %x, want %q", c.in, got, c.want)
		}
	}
}
