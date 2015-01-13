package cryptopalslib

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

//*******
// TYPE CONVERSION FUNCTIONS
//**************************

func BytesToString(byteString []byte) string {
	return string(byteString)
}

func StringToBytes(plainString string) []byte {
	return []byte(plainString)
}

//*******
// HEX FUNCTIONS
//****************

func HexEncodeStringToString(plainStr string) string {
	plainBytes := []byte(plainStr)
	encodedStr := hex.EncodeToString(plainBytes)
	return encodedStr
}

func HexDecodeStringToString(encodedStr string) (string, error) {
	hexBytes, err := hex.DecodeString(encodedStr)
	if err != nil {
		fmt.Println("Error decoding hexadecimal string: ", err)
		return "", err
	}
	return string(hexBytes), err
}

func HexEncodeByteArrayToString(plainBytes []byte) string {
	encLen := hex.EncodedLen(len(plainBytes))
	decodedBytes := make([]byte, encLen)
	hex.Encode(decodedBytes, plainBytes)
	decodedStr := string(decodedBytes)
	return decodedStr
}

/* This is how in a normal world, this function would be implemented...
 * The problem is that bytes in byte array are not converted as individual
 * values but getted in groups of two (unicode bullshit) by string().
func HexDecodeByteArrayToString(plainBytes []byte) (string, error) {
	decLen := hex.DecodedLen(len(plainBytes))
	decoded := make([]byte, decLen)
	n, err := hex.Decode(decoded, plainBytes)
	if err != nil {
		fmt.Println("Error decoding hexadecimal string: ", err)
		return "", err
	}
	decodedStr := string(decoded[:n])
	return decodedStr, err
}
*/

// This is how in golang world this function is implemented...
/*
func HexDecodeByteArrayToString(plainBytes []byte) (string, error) {
	hexStr := HexEncodeByteArrayToString(plainBytes)
	decodedStr, err := HexDecodeStringToString(hexStr)
	if err != nil {
		fmt.Println("Error decoding hexadecimal byte array: ", err)
		return "", err
	}
	return decodedStr, err
}*/

func HexDecodeByteArrayToString(plainBytes []byte) (string, error) {
	return string(plainBytes), nil
}

//*******
// BASE64 FUNCTIONS
//*****************

func Base64EncodeStringToString(plainStr string) string {
	plainBytes := []byte(plainStr)
	encodedStr := base64.StdEncoding.EncodeToString(plainBytes)
	return encodedStr
}

func Base64DecodeStringToString(encodedStr string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		fmt.Println("Error decoding base64 string", err)
		return "", err
	}
	decodedStr := string(decodedBytes)
	return decodedStr, err
}

func Base64EncodeByteArrayToString(plainBytes []byte) string {
	encLen := base64.StdEncoding.EncodedLen(len(plainBytes))
	decodedBytes := make([]byte, encLen)
	base64.StdEncoding.Encode(decodedBytes, plainBytes)
	decodedStr := string(decodedBytes)
	return decodedStr
}

func Base64DecodeByteArrayToString(plainBytes []byte) (string, error) {
	decLen := base64.StdEncoding.DecodedLen(len(plainBytes))
	decoded := make([]byte, decLen)
	n, err := base64.StdEncoding.Decode(decoded, plainBytes)
	if err != nil {
		fmt.Println("Error decoding string: ", err)
		return "", err
	}
	decodedStr := string(decoded[:n])
	return decodedStr, err
}
