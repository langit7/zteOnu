// Package hardcode decrypts ZTE /etc/hardcodefile configuration containers.
package hardcode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func offset(in []byte, amount byte) []byte {
	out := make([]byte, len(in))
	for i, value := range in {
		out[i] = value + amount
	}
	return out
}

// DeriveKeyIV reproduces the firmware's hardcode root-key transformation.
func DeriveKeyIV(hardcoded []byte) (key [32]byte, iv [16]byte, err error) {
	if len(hardcoded) < 64 {
		return key, iv, fmt.Errorf("hardcode root key is %d bytes; need at least 64", len(hardcoded))
	}
	keyPhrase := append(offset(hardcoded[5:21], 3), hardcoded[64:]...)
	ivPhrase := offset(hardcoded[7:39], 1)
	key = sha256.Sum256(keyPhrase)
	ivHash := sha256.Sum256(ivPhrase)
	copy(iv[:], ivHash[:16])
	return key, iv, nil
}

// Decrypt reads one hardcodefile container and returns its plaintext records.
func Decrypt(hardcoded []byte, source io.Reader) ([]byte, error) {
	key, iv, err := DeriveKeyIV(hardcoded)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 15*4)
	if _, err := io.ReadFull(source, header); err != nil {
		return nil, fmt.Errorf("read container header: %w", err)
	}
	if binary.BigEndian.Uint32(header) != 0x01020304 || binary.BigEndian.Uint32(header[4:]) != 3 {
		return nil, errors.New("not a ZTE hardcode config file")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv[:])
	var plaintext []byte
	for hasNext := uint32(1); hasNext != 0; {
		record := make([]byte, 12)
		if _, err := io.ReadFull(source, record); err != nil {
			return nil, fmt.Errorf("read record header: %w", err)
		}
		plainLength := binary.BigEndian.Uint32(record)
		cipherLength := binary.BigEndian.Uint32(record[4:])
		hasNext = binary.BigEndian.Uint32(record[8:])
		if cipherLength%aes.BlockSize != 0 {
			return nil, fmt.Errorf("ciphertext length %d is not AES block aligned", cipherLength)
		}
		if plainLength > cipherLength {
			return nil, fmt.Errorf("plaintext length %d exceeds ciphertext length %d", plainLength, cipherLength)
		}
		ciphertext := make([]byte, cipherLength)
		if _, err := io.ReadFull(source, ciphertext); err != nil {
			return nil, fmt.Errorf("read encrypted record: %w", err)
		}
		mode.CryptBlocks(ciphertext, ciphertext)
		plaintext = append(plaintext, ciphertext[:plainLength]...)
	}
	return plaintext, nil
}
