package factory

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/septrum101/zteOnu/app/crypto"
)

func (f *Factory) reset() error {
	// active onu web service first, increase the chances of success
	_, _ = f.cli.R().Get("/")

	resp, err := f.cli.R().SetBody("SendSq.gch").Post("webFac")
	if err != nil {
		return err
	}
	// 400 means the stale session was reset; when the device is already in a
	// factory session it answers 200 with an empty body, which is equally fine.
	if resp.StatusCode() == 400 || (resp.StatusCode() == 200 && resp.String() == "") {
		return nil
	}

	return errors.New(resp.String())
}

func (f *Factory) reqFactoryMode() error {
	resp, err := f.cli.R().SetBody("RequestFactoryMode.gch").Post("webFac")
	// The device accepts the request by closing the connection, which surfaces
	// as an EOF error; any other transport failure is real.
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if err == nil && (resp.StatusCode() < 200 || resp.StatusCode() >= 300) {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), resp.String())
	}
	return nil
}

func (f *Factory) sendSq() (uint8, error) {
	rn, err := crand.Int(crand.Reader, big.NewInt(60))
	if err != nil {
		return 0, fmt.Errorf("generate SendSq challenge: %w", err)
	}
	r := int(rn.Int64())
	resp, err := f.cli.R().SetBody(fmt.Sprintf("SendSq.gch?rand=%d\r\n", r)).Post("webFac")
	if err != nil {
		return 0, err
	}
	if resp.StatusCode() != 200 {
		return 0, errors.New(resp.String())
	}

	body := resp.Body()
	f.rand = r
	if len(body) == 0 {
		f.protocol = 1
		f.aesIndex = r
		f.key, err = deriveKeyPool(1, r, 0)
		return f.protocol, err
	}
	if match := regexp.MustCompile(`^newrand=([0-9]+)$`).FindSubmatch(body); match != nil {
		newRand, parseErr := strconv.Atoi(string(match[1]))
		if parseErr != nil || newRand >= 60 {
			return 0, errors.New("invalid newrand response")
		}
		f.protocol, f.reRand = 2, newRand
		f.aesIndex = ((0x1000193*r)&0x3F ^ newRand) % 60
		f.key, err = deriveKeyPool(2, r, newRand)
		return f.protocol, err
	}
	match := regexp.MustCompile(`(?s)^re_rand=([0-9]+)&([0-9]+)&(.{6})$`).FindSubmatch(body)
	if match == nil {
		return 0, fmt.Errorf("unrecognized SendSq response %q", body)
	}
	reRand, err1 := strconv.Atoi(string(match[1]))
	proofRandom, err2 := strconv.Atoi(string(match[2]))
	if err1 != nil || err2 != nil || reRand >= 60 || proofRandom >= 1<<23 {
		return 0, errors.New("invalid re_rand response")
	}
	f.protocol, f.reRand, f.proofRandom = 3, reRand, proofRandom
	copy(f.bridgeMAC[:], match[3])
	f.bridgeSet = true
	f.aesIndex = ((0x1000193*r)&0x3F ^ reRand) % 60
	f.key, err = deriveKeyPool(3, r, reRand)
	return f.protocol, err
}

func (f *Factory) checkLoginAuth() error {
	command, err := f.loginAuthCommand()
	if err != nil {
		return err
	}

	payload, err := crypto.ECBEncrypt(
		[]byte(command), f.key)
	if err != nil {
		return err
	}

	resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case 200:
		complete := len(resp.Body()) - len(resp.Body())%16
		if complete < 16 {
			return errors.New("truncated authentication response")
		}
		plain, err := crypto.ECBDecrypt(resp.Body()[:complete], f.key)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(plain), "FactoryMode.gch") {
			return fmt.Errorf("invalid authentication response %q", plain)
		}
		return nil
	case 400:
		return errors.New("unknown errors")
	case 401:
		return errors.New("errors user or password")
	default:
		return errors.New(resp.String())
	}
}

func (f *Factory) loginAuthCommand() (string, error) {
	command := fmt.Sprintf("CheckLoginAuth.gch?version50&user=%s&pass=%s", f.user, f.passwd)
	if f.newMode {
		// Newer firmware binds the auth and FactoryMode requests to a
		// monotonically increasing session time in the range 0..999.
		var err error
		f.authTime, err = randomSessionTime(0)
		if err != nil {
			return "", fmt.Errorf("generate factory session time: %w", err)
		}
		f.authTimeSet = true
		command = fmt.Sprintf("CheckLoginAuth.gch?time%d&version61&user=%s&pass=%s", f.authTime, f.user, f.passwd)
	}
	return command, nil
}

// sendInfo sends the SendInfo payload for a single candidate MAC; the device
// answers HTTP 200 only for a MAC it associates with this client.
func (f *Factory) sendInfo(mac [6]byte) error {
	command, err := f.sendInfoCommand(mac)
	if err != nil {
		return err
	}

	payload, err := crypto.ECBEncrypt(command, f.key)
	if err != nil {
		return err
	}
	resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case 200:
		return nil
	case 400:
		return errors.New("unknown errors")
	case 401:
		return errors.New("info error")
	default:
		return errors.New(resp.String())
	}
}

func (f *Factory) sendInfoCommand(mac [6]byte) ([]byte, error) {
	switch f.protocol {
	case 1:
		return []byte("SendInfo.gch?info=6|"), nil
	case 2:
		return append([]byte("SendInfo.gch?info=12|"), MacToEarly2025MagicBytes(mac)...), nil
	case 3:
		if !f.bridgeSet {
			return nil, errors.New("method 3 requires the bridge MAC returned by SendSq")
		}
		switch f.sendInfoProfile {
		case "rerand22":
			return append([]byte("SendInfo.gch?info=22|"), MacToRerand22MagicBytes(f.bridgeMAC, mac)...), nil
		case "", "rerand34":
			return append([]byte("SendInfo.gch?info=34|"), MacToRerand34MagicBytes(f.bridgeMAC, mac)...), nil
		default:
			return nil, fmt.Errorf("unknown method-3 SendInfo profile %q", f.sendInfoProfile)
		}
	default:
		return nil, errors.New("SendSq has not selected a protocol method")
	}
}

func (f *Factory) factoryMode() (user string, pass string, err error) {
	command, err := f.factoryModeCommand()
	if err != nil {
		return "", "", err
	}

	payload, err := crypto.ECBEncrypt([]byte(command), f.key)
	if err != nil {
		return
	}
	resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
	if err != nil {
		return
	}
	if resp.StatusCode() != 200 {
		return "", "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), resp.String())
	}

	dec, err := crypto.ECBDecrypt(resp.Body(), f.key)
	if err != nil {
		return
	}

	u, err := url.Parse(string(dec))
	if err != nil {
		return
	}

	q := u.Query()
	user = q.Get("user")
	pass = q.Get("pass")
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("factory mode response carries no credentials: %q", string(dec))
	}

	return
}

func (f *Factory) factoryModeCommand() (string, error) {
	return f.factoryModeCommandForAction("open")
}

func (f *Factory) factoryModeCommandForAction(action string) (string, error) {
	if action == "close" {
		return "FactoryMode.gch?close", nil
	}
	command := "FactoryMode.gch?mode=2&user=notused"
	if f.newMode {
		if !f.authTimeSet {
			return "", errors.New("new factory method has no authentication session time")
		}
		modeTime, timeErr := randomSessionTime(f.authTime)
		if timeErr != nil {
			return "", fmt.Errorf("generate factory mode session time: %w", timeErr)
		}
		command = fmt.Sprintf("FactoryMode.gch?time%d&mode=2&user=notused", modeTime)
	}
	return command, nil
}

// CloseFactoryMode authenticates then closes the temporary Telnet service.
func (f *Factory) closeFactoryMode() error {
	command, _ := f.factoryModeCommandForAction("close")
	payload, err := crypto.ECBEncrypt([]byte(command), f.key)
	if err != nil {
		return err
	}
	resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), resp.String())
	}
	if len(resp.Body()) != 0 {
		complete := len(resp.Body()) - len(resp.Body())%16
		if complete == 0 {
			return errors.New("truncated close response")
		}
		if _, err := crypto.ECBDecrypt(resp.Body()[:complete], f.key); err != nil {
			return err
		}
	}
	return nil
}

// SerialSilence controls /proc/serial after the shared authentication flow.
func (f *Factory) serialSilence(action string) error {
	command := fmt.Sprintf("SerialSlience.gch?action=%s", action)
	payload, err := crypto.ECBEncrypt([]byte(command), f.key)
	if err != nil {
		return err
	}
	resp, err := f.cli.R().SetBody(payload).Post("webFacEntry")
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode(), resp.String())
	}
	return nil
}

// randomSessionTime returns a value in [minimum, 1000). The device only
// compares ordering, but keeping the value bounded matches the firmware's
// parser and the established client handshake.
func randomSessionTime(minimum int) (int, error) {
	if minimum < 0 {
		minimum = 0
	}
	if minimum >= 1000 {
		return 999, nil
	}
	span := big.NewInt(int64(1000 - minimum))
	n, err := crand.Int(crand.Reader, span)
	if err != nil {
		return 0, err
	}
	return minimum + int(n.Int64()), nil
}

func (f *Factory) handle(mac *[6]byte) (tlUser string, tlPass string, err error) {
	fmt.Print("step [0] reset factory: ")
	if err = f.reset(); err != nil {
		return
	}
	fmt.Println("ok")

	fmt.Print("step [1] request factory mode: ")
	if err = f.reqFactoryMode(); err != nil {
		return
	}
	fmt.Println("ok")

	var ver uint8
	fmt.Print("step [2] send sq: ")
	ver, err = f.sendSq()
	if err != nil {
		return
	}
	fmt.Println("ok")

	fmt.Print("step [3] check login auth: ")
	switch ver {
	case 1:
		if err = f.checkLoginAuth(); err != nil {
			return
		}
	case 2, 3:
		if mac == nil {
			selected, macErr := f.ClientMAC()
			if macErr != nil {
				err = fmt.Errorf("device requires a client MAC (SendInfo): %w", macErr)
				return
			}
			mac = &selected
		}
		if err = f.sendInfo(*mac); err != nil {
			return
		}
		if err = f.checkLoginAuth(); err != nil {
			return
		}
	}
	fmt.Println("ok")

	fmt.Print("step [4] enter factory mode: ")
	tlUser, tlPass, err = f.factoryMode()
	if err != nil {
		fmt.Println("fail")
		return
	}
	fmt.Println("ok")
	return
}

// HandleMAC runs the full webFac flow with the given candidate MAC used for
// the SendInfo payload and returns the granted temp telnet credentials. The
// HTTP flow returns credentials even for a MAC the device will not honor over
// telnet, so the caller must verify each result with an actual telnet login
// and fall through to the next candidate MAC when it fails.
func (f *Factory) HandleMAC(mac [6]byte) (tlUser string, tlPass string, err error) {
	return f.handle(&mac)
}

// Handle runs the flow and selects a client MAC only if the detected protocol
// generation requires one.
func (f *Factory) Handle() (tlUser string, tlPass string, err error) {
	return f.handle(nil)
}

func (f *Factory) authenticate(mac *[6]byte) error {
	if err := f.reset(); err != nil {
		return err
	}
	if err := f.reqFactoryMode(); err != nil {
		return err
	}
	method, err := f.sendSq()
	if err != nil {
		return err
	}
	if method == 2 || method == 3 {
		if mac == nil {
			selected, macErr := f.ClientMAC()
			if macErr != nil {
				return fmt.Errorf("device requires a client MAC (SendInfo): %w", macErr)
			}
			mac = &selected
		}
		if err := f.sendInfo(*mac); err != nil {
			return err
		}
	}
	return f.checkLoginAuth()
}

// CloseTelnet runs the factory authentication flow and closes Telnet.
func (f *Factory) CloseTelnet(mac [6]byte) error {
	if err := f.authenticate(&mac); err != nil {
		return err
	}
	return f.closeFactoryMode()
}

func (f *Factory) CloseTelnetAuto() error {
	if err := f.authenticate(nil); err != nil {
		return err
	}
	return f.closeFactoryMode()
}

// Serial runs the factory authentication flow and changes serial state.
func (f *Factory) Serial(mac [6]byte, action string) error {
	if action != "open" && action != "close" {
		return fmt.Errorf("invalid serial action %q", action)
	}
	if err := f.authenticate(&mac); err != nil {
		return err
	}
	return f.serialSilence(action)
}

func (f *Factory) SerialAuto(action string) error {
	if action != "open" && action != "close" {
		return fmt.Errorf("invalid serial action %q", action)
	}
	if err := f.authenticate(nil); err != nil {
		return err
	}
	return f.serialSilence(action)
}
