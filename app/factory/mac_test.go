package factory

import "testing"

func TestParseAndFormatMAC(t *testing.T) {
	for _, input := range []string{"00:07:29:55:35:57", "00-07-29-55-35-57", "0007.2955.3557"} {
		mac, err := ParseMAC(input)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", input, err)
		}
		if got := FormatMAC(mac); got != "00:07:29:55:35:57" {
			t.Fatalf("FormatMAC = %q", got)
		}
	}
	if _, err := ParseMAC("00:11:22:33:44"); err == nil {
		t.Fatal("expected invalid length")
	}
}
