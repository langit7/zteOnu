package factory

import (
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

// Factory drives the reverse-engineered webFac HTTP flow of the ONU.
type Factory struct {
	user            string
	passwd          string
	ip              string
	port            int
	iface           string
	mac             string
	newMode         bool
	cli             *resty.Client
	key             []byte
	protocol        uint8
	rand            int
	reRand          int
	proofRandom     int
	bridgeMAC       [6]byte
	bridgeSet       bool
	aesIndex        int
	sendInfoProfile string
	authTime        int
	authTimeSet     bool
}

// New builds a Factory for the given device and client settings. A non-empty
// mac is the only candidate used for the SendInfo payload (see ClientMAC).
func New(user string, passwd string, ip string, port int, iface string, mac string) *Factory {
	return NewWithMode(user, passwd, ip, port, iface, mac, false)
}

// NewWithMode builds a Factory and optionally enables the newer
// time-qualified version61 handshake. New keeps the historical behavior so
// existing library callers do not change protocol paths unexpectedly.
func NewWithMode(user string, passwd string, ip string, port int, iface string, mac string, newMode bool) *Factory {
	return NewWithProfile(user, passwd, ip, port, iface, mac, newMode, "rerand34")
}

// NewWithProfile also selects the method-3 proof format. Supported profiles
// are rerand34 (current F6201B) and rerand22 (compatibility firmware).
func NewWithProfile(user string, passwd string, ip string, port int, iface string, mac string, newMode bool, profile string) *Factory {
	return &Factory{
		user:            user,
		passwd:          passwd,
		ip:              ip,
		port:            port,
		iface:           iface,
		mac:             mac,
		newMode:         newMode,
		sendInfoProfile: profile,
		cli: resty.New().
			SetHeader("User-Agent", "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36").
			SetHeader("Referer", fmt.Sprintf("http://%s/login.html", ip)).
			SetTimeout(10 * time.Second).
			SetBaseURL(fmt.Sprintf("http://%s:%d", ip, port)),
	}
}
