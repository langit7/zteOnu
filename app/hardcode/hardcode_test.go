package hardcode

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestDecryptRoundTrip(t *testing.T) {
	root := bytes.Repeat([]byte("root-key-material"), 5)
	key, iv, err := DeriveKeyIV(root)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key[:])
	enc := cipher.NewCBCEncrypter(block, iv[:])
	plain1 := []byte("first record\x00\x00\x00\x00")
	plain2 := []byte("second record\x00\x00")
	for len(plain1)%16 != 0 {
		plain1 = append(plain1, 0)
	}
	for len(plain2)%16 != 0 {
		plain2 = append(plain2, 0)
	}
	c1, c2 := append([]byte{}, plain1...), append([]byte{}, plain2...)
	enc.CryptBlocks(c1, c1)
	enc.CryptBlocks(c2, c2)
	container := make([]byte, 60)
	binary.BigEndian.PutUint32(container, 0x01020304)
	binary.BigEndian.PutUint32(container[4:], 3)
	appendRecord := func(plainLen uint32, encrypted []byte, next uint32) {
		header := make([]byte, 12)
		binary.BigEndian.PutUint32(header, plainLen)
		binary.BigEndian.PutUint32(header[4:], uint32(len(encrypted)))
		binary.BigEndian.PutUint32(header[8:], next)
		container = append(container, header...)
		container = append(container, encrypted...)
	}
	appendRecord(uint32(len("first record")), c1, 1)
	appendRecord(uint32(len("second record")), c2, 0)
	got, err := Decrypt(root, bytes.NewReader(container))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first recordsecond record" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptRejectsBadMagic(t *testing.T) {
	root := bytes.Repeat([]byte("root-key-material"), 5)
	_, err := Decrypt(root, bytes.NewReader(make([]byte, 60)))
	if err == nil {
		t.Fatal("expected bad magic error")
	}
}
