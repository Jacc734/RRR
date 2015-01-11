package main

import (
	"cryptopalslib"
	"fmt"
)

func main() {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Println("Input hex string: ", input)
	hexStr, err := cryptopalslib.HexDecodeStringToString(input)
	if err != nil {
		fmt.Println("Error decoding hex string")
		return
	}
	encodedStr := cryptopalslib.Base64EncodeStringToString(hexStr)
	fmt.Println("Base64 encoded: ", encodedStr)

	decodedStr, _ := cryptopalslib.Base64DecodeStringToString(encodedStr)
	fmt.Println("Base64 decoded: ", decodedStr)

	fmt.Println("")

	newInput := "Encoded in Base64"
	fmt.Println("Input ASCII string: ", newInput)

	newEncodedStr := cryptopalslib.Base64EncodeByteArrayToString([]byte(newInput))
	fmt.Println("Base64 Encoded: ", newEncodedStr)

	newDecodedStr, _ := cryptopalslib.Base64DecodeByteArrayToString([]byte(newEncodedStr))
	fmt.Println("Base64 Decoded: ", newDecodedStr)
}
