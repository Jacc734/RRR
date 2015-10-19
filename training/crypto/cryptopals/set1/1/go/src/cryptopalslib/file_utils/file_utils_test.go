package file_utils

import (
	"reflect" // used to compare "complex" types (slices)
	"testing"
)

func TestWriteAndReadFile(t *testing.T) {
	t.Log("Executing TestWriteAndReadFile...")

	cases := []struct {
		in   string
		want []byte
	}{
		{"/tmp/test_file.txt", []byte("test content")},
	}
	for _, c := range cases {
		WriteFile(c.in, []byte(c.want))
		got, err := ReadFile(c.in)
		if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("ReadFile(%q) => %q, want %q. Error: %v", c.in, got,
				c.want, err)
		}
	}
}

func TestReadHexFile(t *testing.T) {
	t.Log("Executing TestReadHexFile...")

	cases := []struct {
		in   []byte
		want []byte
	}{
		{[]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
			[]byte("I'm killing your brain like a poisonous mushroom")},
	}
	for _, c := range cases {
		filePath, errTemp := WriteTMPFile(c.in)
		if errTemp != nil {
			t.Errorf("Failed to create temp hex file. Error: %v", errTemp)
		}
		got, err := ReadHexEncodedFile(filePath)
		if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("ReadFile(%q) => %q, want %q. Error: %v", c.in, got,
				c.want, err)
		}
	}
}

func TestWriteTMPFile(t *testing.T) {
	t.Log("Executing TestWriteTMPFile...")

	cases := []struct {
		in   []byte
		want []byte
	}{
		{[]byte("test content"), []byte("test content")},
	}
	for _, c := range cases {
		filePath, errTemp := WriteTMPFile(c.in)
		t.Log("Temp file created: ", filePath)
		got, errRead := ReadFile(filePath)
		if reflect.DeepEqual(got, c.want) == false {
			t.Errorf("ReadFile(%q) => %q, want %q. ErrorWriteTMP: %v,"+
				"ErrorReadFile: %v", c.in, got, c.want, errTemp, errRead)
		}
	}
}
