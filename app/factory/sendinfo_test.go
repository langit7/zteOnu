package factory

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mac6(s string) [6]byte {
	var out [6]byte
	b, _ := hex.DecodeString(s)
	copy(out[:], b)
	return out
}

func TestRerand22PayloadMatchesPythonTrace(t *testing.T) {
	f := New("user", "pass", "192.0.2.1", 80, "", "")
	f.protocol, f.bridgeMAC, f.bridgeSet, f.sendInfoProfile = 3, mac6("0c014b40a9ca"), true, "rerand22"
	got, err := f.sendInfoCommand(mac6("000729553557"))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("SendInfo.gch?info=22|"), []byte("apjdapalapjdafpelleflleglocxllcyllmyllmvlltnlluglllullfdllarllyflltnlluglllullfdllarllyf")...)
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestRerand34PayloadShapeAndVerification(t *testing.T) {
	bridge, client := mac6("843c996404e5"), mac6("000729553557")
	payload := MacToRerand34MagicBytes(bridge, client)
	if len(payload) != 34*4 {
		t.Fatalf("payload length %d", len(payload))
	}
	if !VerifyRerand34Payload(payload, bridge, client, 11) {
		t.Fatal("generated rerand34 payload rejected")
	}
}

func TestEarly2025PayloadShapeAndVerification(t *testing.T) {
	client := mac6("000729553557")
	payload := MacToEarly2025MagicBytes(client)
	if len(payload) != 46 {
		t.Fatalf("payload length %d", len(payload))
	}
	if !verifyPayload(payload, client) {
		t.Fatal("generated info=12 payload rejected")
	}
}
