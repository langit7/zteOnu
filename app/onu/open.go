package onu

import (
	"errors"
	"fmt"
	"strings"

	"github.com/septrum101/zteOnu/app/factory"
	"github.com/septrum101/zteOnu/app/telnet"
)

// Options carries the device and client settings for OpenTempTelnet.
type Options struct {
	User            string
	Pass            string
	IP              string
	HTTPPort        int
	TelnetPort      int
	Iface           string
	Mac             string
	NewMethod       bool
	SendInfoProfile string
	Users           []string
	Passes          []string
}

func credentials(opts Options) ([]string, []string) {
	users, passes := opts.Users, opts.Passes
	if len(users) == 0 {
		users = []string{opts.User}
	}
	if len(passes) == 0 {
		passes = []string{opts.Pass}
	}
	return users, passes
}

// OpenTempTelnet runs the webFac flow for the client MAC selected by --iface,
// --mac or the route-based auto-detection and verifies the granted temp
// credentials with a real telnet login. The HTTP flow returns credentials even
// when the MAC is not honored, so the run only succeeds if the credentials
// actually log in; on failure the returned connection is nil.
func OpenTempTelnet(opts Options) (*telnet.Telnet, string, string, error) {
	users, passes := credentials(opts)
	var failures []error
	for _, user := range users {
		for _, pass := range passes {
			fmt.Printf("trying user %q pass %q\n", user, pass)
			fac := factory.NewWithProfile(user, pass, opts.IP, opts.HTTPPort, opts.Iface, opts.Mac, opts.NewMethod, opts.SendInfoProfile)
			fmt.Println(strings.Repeat("-", 35))
			tlUser, tlPass, err := fac.Handle()
			if err != nil {
				failures = append(failures, fmt.Errorf("%s/%s: %w", user, pass, err))
				continue
			}
			fmt.Printf("temp user: %s, pass: %s\n", tlUser, tlPass)
			t, err := telnet.New(tlUser, tlPass, opts.IP, opts.TelnetPort)
			if err == nil {
				err = t.Login()
			}
			if err != nil {
				if t != nil {
					t.Conn.Close()
				}
				failures = append(failures, fmt.Errorf("%s/%s telnet verification: %w", user, pass, err))
				continue
			}
			fmt.Println(strings.Repeat("-", 35))
			return t, tlUser, tlPass, nil
		}
	}
	return nil, "", "", fmt.Errorf("no factory credentials succeeded: %w", errors.Join(failures...))
}

func ControlTelnet(opts Options, action string) error {
	if action != "close" {
		return fmt.Errorf("unsupported Telnet control action %q", action)
	}
	users, passes := credentials(opts)
	var failures []error
	for _, user := range users {
		for _, pass := range passes {
			fac := factory.NewWithProfile(user, pass, opts.IP, opts.HTTPPort, opts.Iface, opts.Mac, opts.NewMethod, opts.SendInfoProfile)
			if err := fac.CloseTelnetAuto(); err == nil {
				return nil
			} else {
				failures = append(failures, err)
			}
		}
	}
	return fmt.Errorf("no factory credentials succeeded: %w", errors.Join(failures...))
}

func ControlSerial(opts Options, action string) error {
	users, passes := credentials(opts)
	var failures []error
	for _, user := range users {
		for _, pass := range passes {
			fac := factory.NewWithProfile(user, pass, opts.IP, opts.HTTPPort, opts.Iface, opts.Mac, opts.NewMethod, opts.SendInfoProfile)
			if err := fac.SerialAuto(action); err == nil {
				return nil
			} else {
				failures = append(failures, err)
			}
		}
	}
	return fmt.Errorf("no factory credentials succeeded: %w", errors.Join(failures...))
}
