package factory

import (
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
)

// Factory drives the reverse-engineered webFac HTTP flow of the ONU.
type Factory struct {
	user        string
	passwd      string
	ip          string
	port        int
	iface       string
	mac         string
	newMode     bool
	cli         *resty.Client
	key         []byte
	authTime    int
	authTimeSet bool
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
	return &Factory{
		user:    user,
		passwd:  passwd,
		ip:      ip,
		port:    port,
		iface:   iface,
		mac:     mac,
		newMode: newMode,
		cli: resty.New().SetHeader("User-Agent", "curl/8.8.0-DEV").
			SetTimeout(10 * time.Second).
			SetBaseURL(fmt.Sprintf("http://%s:%d", ip, port)),
	}
}
