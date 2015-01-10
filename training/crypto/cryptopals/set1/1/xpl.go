package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

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

func Base64EncodeByteArrayToString(plainStr []byte) string {
	plainBytes := []byte(plainStr)
	decLen := base64.StdEncoding.EncodedLen(len(plainStr))
	decodedBytes := make([]byte, decLen)
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

func main() {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Println("Input hex string: ", input)
	hexBytes, err := hex.DecodeString(input)
	if err != nil {
		fmt.Println("Error decoding hex string")
		return
	}
	encodedStr := Base64EncodeStringToString(string(hexBytes))
	fmt.Println("Base64 encoded: ", encodedStr)

	decodedStr, _ := Base64DecodeStringToString(encodedStr)
	fmt.Println("Base64 decoded: ", decodedStr)

	newInput := "Encoded in Base64"
	fmt.Println("Input string: ", newInput)

	newEncodedStr := Base64EncodeByteArrayToString([]byte(newInput))
	fmt.Println("Base64 Encoded: ", newEncodedStr)

	newDecodedStr, _ := Base64DecodeByteArrayToString([]byte(newEncodedStr))
	fmt.Println("Base64 Decoded: ", newDecodedStr)
}
