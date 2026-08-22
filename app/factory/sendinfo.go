package factory

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Device-side SendInfo verification, reversed from the webFacCheckClientInfo
// VM (see zte_payload.py):
//
//  1. info must be "<N>|<payload>", with N%6==0 and N<=512.
//  2. Each 4-byte group of the payload is read as a little-endian value w and
//     the VM computes acc = 1; then repeats 1271 times acc = (acc * w) % 2537,
//     i.e. acc = w^1271 mod 2537. byte_buf[k] = acc & 0xff.
//  3. byte_buf is grouped by 6 bytes; if any group equals the client MAC, the
//     request is authorized.
//
// The payload is therefore 46 bytes = 12 little-endian uint16 values
// ("info=12"), each packed as 2 data bytes + 2 zero bytes (the 12th value has
// no trailing zero bytes). The first 6 values are modular-exponentiation
// preimages of the 6 MAC bytes: for each MAC byte m we pick a value v with
// (v^1271 mod 2537) & 0xff == m. The remaining 6 values are filler that does
// not take part in the MAC match.
const (
	mod = 0x9E9     // 2537
	exp = 0x4F8 - 1 // 1271 (the VM counter counts down from 0x4f8 to 1)
)

// power returns w^exp mod mod, equivalent to the device VM's multiply loop.
func power(w uint32) byte {
	w %= mod
	acc := uint32(1)
	for e := exp; e > 0; e >>= 1 {
		if e&1 == 1 {
			acc = (acc * w) % mod
		}
		w = (w * w) % mod
	}
	return byte(acc & 0xff)
}

// revTable maps every byte value to the preimages v in [0, mod) satisfying
// power(v) == that byte, in ascending order.
var revTable [256][]uint16

func init() {
	var buckets [256][]uint16
	for v := range uint16(mod) {
		b := power(uint32(v))
		buckets[b] = append(buckets[b], v)
	}
	for b := range 256 {
		if len(buckets[b]) == 0 {
			panic(fmt.Sprintf("no preimage for byte %02x", b))
		}
		revTable[b] = buckets[b]
	}
}

// MacToMagicBytes builds the 46-byte SendInfo magic payload that encodes the
// given client MAC. The first six uint16 values are the smallest preimages of
// the six MAC bytes; the remaining six are fixed filler values that do not
// affect the MAC check.
func MacToMagicBytes(mac [6]byte) []byte {
	vals := make([]uint16, 12)
	for i, b := range mac {
		vals[i] = revTable[b][0]
	}
	out := make([]byte, 0, 46)
	for _, v := range vals[:11] {
		out = append(out, byte(v), byte(v>>8), 0, 0)
	}
	return append(out, byte(vals[11]), byte(vals[11]>>8))
}

// MacToEarly2025MagicBytes is the explicit name for the historical info=12
// payload. MacToMagicBytes remains as a compatibility alias.
func MacToEarly2025MagicBytes(mac [6]byte) []byte { return MacToMagicBytes(mac) }

const (
	headerExponent            = uint32(0x1687)
	headerModulus             = uint32(0x7561)
	selectedModulus           = headerExponent
	rerand34HeaderModulusWord = uint32(9893)
)

var (
	payloadAlphabet = []byte("lmaoztebcdfghijknpqrsuvwxy")
	rerand34Marker  = [6]byte{0x00, 0xff, 0x72, 0x46, 0x34, 0x11}
	headerEncoding  map[uint32]uint32
	macEncoding     [256]uint32
)

func powMod(base, exponent, modulus uint32) uint32 {
	if modulus == 0 {
		return 0
	}
	base %= modulus
	result := uint64(1)
	for exponent > 0 {
		if exponent&1 != 0 {
			result = result * uint64(base) % uint64(modulus)
		}
		base = uint32(uint64(base) * uint64(base) % uint64(modulus))
		exponent >>= 1
	}
	return uint32(result)
}

func forEachAlphabetWord(fn func(uint32) bool) {
	for _, a := range payloadAlphabet {
		for _, b := range payloadAlphabet {
			for _, c := range payloadAlphabet {
				for _, d := range payloadAlphabet {
					word := uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
					if fn(word) {
						return
					}
				}
			}
		}
	}
}

func initMethod3Encodings() {
	required := make(map[uint32]struct{})
	for value := uint32(0); value < headerModulus; value++ {
		required[powMod(value, headerExponent, headerModulus)] = struct{}{}
	}
	headerEncoding = make(map[uint32]uint32, len(required))
	forEachAlphabetWord(func(word uint32) bool {
		result := powMod(word, headerExponent, headerModulus)
		if _, needed := required[result]; needed {
			if _, exists := headerEncoding[result]; !exists {
				headerEncoding[result] = word
			}
		}
		return len(headerEncoding) == len(required)
	})
	if len(headerEncoding) != len(required) {
		panic("restricted SendInfo alphabet cannot encode every header value")
	}

	seen := 0
	forEachAlphabetWord(func(word uint32) bool {
		result := byte(powMod(word, 1, selectedModulus))
		if macEncoding[result] == 0 {
			macEncoding[result] = word
			seen++
		}
		return seen == 256
	})
	if seen != 256 {
		panic("restricted SendInfo alphabet cannot encode every MAC byte")
	}
}

func init() { initMethod3Encodings() }

// CreatePayloadWords builds the method-3 22-word proof. Its header cancels
// the server proof index and the decoded groups match bridge then client MAC.
func CreatePayloadWords(bridgeMAC, clientMAC [6]byte) []uint32 {
	words := []uint32{
		headerEncoding[0], headerEncoding[1],
		headerEncoding[0], headerEncoding[selectedModulus],
	}
	for _, b := range bridgeMAC {
		words = append(words, macEncoding[b])
	}
	for twice := 0; twice < 2; twice++ {
		for _, b := range clientMAC {
			words = append(words, macEncoding[b])
		}
	}
	return words
}

// MacToRerand22MagicBytes serializes the compatibility method-3 proof.
func MacToRerand22MagicBytes(bridgeMAC, clientMAC [6]byte) []byte {
	words := CreatePayloadWords(bridgeMAC, clientMAC)
	out := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	return out
}

// CreateRerand34PayloadWords builds the current F6201B 34-word proof.
func CreateRerand34PayloadWords(bridgeMAC, clientMAC [6]byte) []uint32 {
	words := []uint32{0, 1, 0, rerand34HeaderModulusWord}
	appendBytes := func(values []byte) {
		for _, value := range values {
			words = append(words, uint32(value))
		}
	}
	appendBytes(bridgeMAC[:])
	appendBytes(clientMAC[:])
	appendBytes(clientMAC[:])
	appendBytes(rerand34Marker[:])
	appendBytes(rerand34Marker[:])
	return words
}

// MacToRerand34MagicBytes serializes the latest method-3 proof.
func MacToRerand34MagicBytes(bridgeMAC, clientMAC [6]byte) []byte {
	words := CreateRerand34PayloadWords(bridgeMAC, clientMAC)
	out := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	return out
}

func VerifyRerand22Payload(payload []byte, bridgeMAC, clientMAC [6]byte, proofIndex uint32) bool {
	if len(payload)%4 != 0 || len(payload) < 40 {
		return false
	}
	words := make([]uint32, len(payload)/4)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(payload[i*4:])
	}
	header := [4]uint32{}
	for i := range header {
		header[i] = powMod(words[i], headerExponent, headerModulus)
	}
	exponent := header[0]*proofIndex + header[1]
	modulus := header[2]*proofIndex + header[3]
	if modulus == 0 {
		return false
	}
	decoded := make([]byte, len(words)-4)
	for i, word := range words[4:] {
		decoded[i] = byte(powMod(word, exponent, modulus))
	}
	if len(decoded) < 6 || !bytes.Equal(decoded[:6], bridgeMAC[:]) {
		return false
	}
	for offset := 6; offset+6 <= len(decoded); offset += 6 {
		if bytes.Equal(decoded[offset:offset+6], clientMAC[:]) {
			return true
		}
	}
	return false
}

func VerifyRerand34Payload(payload []byte, bridgeMAC, clientMAC [6]byte, proofIndex uint32) bool {
	if len(payload) != 34*4 {
		return false
	}
	words := make([]uint32, 34)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(payload[i*4:])
	}
	exponent := powMod(words[0], headerExponent, headerModulus)*proofIndex + powMod(words[1], headerExponent, headerModulus)
	modulus := powMod(words[2], headerExponent, headerModulus)*proofIndex + powMod(words[3], headerExponent, headerModulus)
	if exponent != 1 || modulus != headerExponent {
		return false
	}
	want := append([]byte{}, bridgeMAC[:]...)
	want = append(want, clientMAC[:]...)
	want = append(want, clientMAC[:]...)
	want = append(want, rerand34Marker[:]...)
	want = append(want, rerand34Marker[:]...)
	decoded := make([]byte, 30)
	for i, word := range words[4:] {
		decoded[i] = byte(powMod(word, exponent, modulus))
	}
	return bytes.Equal(decoded, want)
}

// verifyPayload replicates the device-side check: split the payload into
// 4-byte groups, apply power() to each, group the resulting bytes by 6, and
// report whether any group equals mac.
func verifyPayload(payload []byte, mac [6]byte) bool {
	var bb [12]byte
	for k := range 12 {
		var w uint32
		for i := range 4 {
			if idx := 4*k + i; idx < len(payload) {
				w |= uint32(payload[idx]) << (8 * i)
			}
		}
		bb[k] = power(w)
	}
	for i := range 12 / 6 {
		if bytes.Equal(bb[6*i:6*i+6], mac[:]) {
			return true
		}
	}
	return false
}
