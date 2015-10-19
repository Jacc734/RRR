package main

import (
	EncodingUtils "cryptopalslib/encoding_utils"
	FileUtils "cryptopalslib/file_utils"
	"fmt"
)

func main() {
	inputBytes, err := FileUtils.ReadHexEncodedFile("input.txt")
	if err != nil {
		return
	}

	encodedStr := EncodingUtils.Base64EncodeByteArrayToString(inputBytes)
	fmt.Println("Base64 encoded: ", encodedStr)

	/* Extra stuff
	decodedStr, _ := EncodingUtils.Base64DecodeStringToString(encodedStr)
	fmt.Println("Base64 decoded: ", decodedStr)

	fmt.Println("")

	newInput := "Encoded in Base64"
	fmt.Println("Input ASCII string: ", newInput)

	newEncodedStr := EncodingUtils.Base64EncodeByteArrayToString(
		[]byte(newInput))
	fmt.Println("Base64 Encoded: ", newEncodedStr)

	newDecodedStr, _ := EncodingUtils.Base64DecodeByteArrayToString(
		[]byte(newEncodedStr))
	fmt.Println("Base64 Decoded: ", newDecodedStr)*/
}
