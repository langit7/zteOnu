package factory

import (
	"strings"
	"testing"
)

func TestFactoryDefaultCommandsRemainUnchanged(t *testing.T) {
	f := New("telecomadmin", "secret", "192.168.1.1", 8080, "", "")

	login, err := f.loginAuthCommand()
	if err != nil {
		t.Fatal(err)
	}
	if login != "CheckLoginAuth.gch?version50&user=telecomadmin&pass=secret" {
		t.Fatalf("unexpected default auth command: %q", login)
	}

	mode, err := f.factoryModeCommand()
	if err != nil {
		t.Fatal(err)
	}
	if mode != "FactoryMode.gch?mode=2&user=notused" {
		t.Fatalf("unexpected default factory command: %q", mode)
	}
}

func TestNewFactoryCommandsUseOrderedSessionTimes(t *testing.T) {
	f := NewWithMode("telecomadmin", "secret", "192.168.1.1", 8080, "", "", true)

	login, err := f.loginAuthCommand()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(login, "CheckLoginAuth.gch?time") || !strings.Contains(login, "&version61&user=telecomadmin&pass=secret") {
		t.Fatalf("unexpected new auth command: %q", login)
	}

	mode, err := f.factoryModeCommand()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mode, "FactoryMode.gch?time") || !strings.HasSuffix(mode, "&mode=2&user=notused") {
		t.Fatalf("unexpected new factory command: %q", mode)
	}

	if !f.authTimeSet || f.authTime < 0 || f.authTime >= 1000 {
		t.Fatalf("invalid auth session time: set=%t value=%d", f.authTimeSet, f.authTime)
	}
}

func TestNewFactoryModeRequiresAuthTime(t *testing.T) {
	f := NewWithMode("telecomadmin", "secret", "192.168.1.1", 8080, "", "", true)
	if _, err := f.factoryModeCommand(); err == nil {
		t.Fatal("expected factory mode to require the auth session time")
	}
}

func TestLatestKeySliceMatchesReference(t *testing.T) {
	key, err := deriveKeyPool(3, 0, 40)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x90, 0x88, 0x8a, 0x44, 0x7b, 0xe9, 0xd2, 0x50, 0xbf, 0xc0, 0x74, 0x5b, 0xbd, 0xe6, 0x2b, 0x02, 0xe7, 0xad, 0xa1, 0xdd, 0x70, 0x41, 0x56, 0x91}
	if string(key) != string(want) {
		t.Fatalf("unexpected latest key: %x", key)
	}
}
