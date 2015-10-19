package file_utils

import (
	"encoding/hex"
	"io/ioutil"
	"log"
)

func ReadFile(filePath string) ([]byte, error) {
	c, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("File (%s) could not be opened. Error: %v", filePath, err)
	}
	return c, err
}

func ReadHexEncodedFile(filePath string) ([]byte, error) {
	c, errReadFile := ioutil.ReadFile(filePath)
	if errReadFile != nil {
		log.Printf("File (%s) could not be opened. Error: %v", filePath, errReadFile)
		return []byte(""), errReadFile
	}
	hexStr := string(c)
	decodedHexStr, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Printf("File contents could not be hex decoded. Error: %v", err)
	}
	return decodedHexStr, err
}

func WriteFile(filePath string, data []byte) error {
	err := ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		log.Printf("File (%s) could not be written. Error: %v", filePath, err)
	}
	return err
}

func WriteTMPFile(data []byte) (string, error) {
	fd, err := ioutil.TempFile("", "crypto_")
	if err != nil {
		log.Printf("Temporary file could not be created")
		return "", err
	}
	filePath := fd.Name()
	err = fd.Close()
	if err != nil {
		log.Printf("File (%s) could not be closed. Error: %v", err)
		return filePath, err
	}
	return filePath, WriteFile(filePath, data)
}
