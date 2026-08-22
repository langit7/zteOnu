package crypto

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
)

func ECBEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	origData = padding(origData, block.BlockSize())
	encrypted := make([]byte, len(origData))
	// encrypt each block
	for i := 0; i < len(origData); i += block.BlockSize() {
		block.Encrypt(encrypted[i:i+block.BlockSize()], origData[i:i+block.BlockSize()])
	}
	return encrypted, nil
}

func ECBDecrypt(encrypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(encrypted)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("AES-ECB ciphertext length %d is not block aligned", len(encrypted))
	}

	origData := make([]byte, len(encrypted))
	// decrypt each block
	for i := 0; i < len(encrypted); i += block.BlockSize() {
		block.Decrypt(origData[i:i+block.BlockSize()], encrypted[i:i+block.BlockSize()])
	}
	origData = unPadding(origData)
	return origData, nil
}

func padding(origData []byte, blockSize int) []byte {
	padding := (-len(origData)) % blockSize
	if padding < 0 {
		padding += blockSize
	}
	padText := bytes.Repeat([]byte{0}, padding)
	return append(origData, padText...)
}

func unPadding(origData []byte) []byte {
	return bytes.TrimRight(origData, "\x00")
}

func Base64Decrypt(b64 string, key []byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	decrypted, err := ECBDecrypt(encrypted, key)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
