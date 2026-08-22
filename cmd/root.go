package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/septrum101/zteOnu/app/onu"
	"github.com/septrum101/zteOnu/version"
)

var (
	// Used for flags.
	users           []string
	passwords       []string
	ip              string
	port            int
	telnet          bool // write permanent telnet settings, apply by in-place telnetd restart
	telnetRestart   bool // write permanent telnet settings, apply by device reboot
	telnetPort      int
	iface           string
	mac             string
	newMethod       bool
	sendInfoProfile string

	rootCmd = &cobra.Command{
		Use:   "zteOnu",
		Short: "Control ZTE ONU factory-mode features",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runTelnet("open"); err != nil {
				fmt.Println(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringSliceVarP(&users, "user", "u", []string{
		"factorymode", "CMCCAdmin", "CUAdmin", "telecomadmin", "cqadmin",
		"user", "admin", "cuadmin", "lnadmin", "useradmin",
	}, "factory mode auth usernames (comma-separated)")
	rootCmd.PersistentFlags().StringSliceVarP(&passwords, "pass", "p", []string{
		"nE%jA@5b", "aDm8H%MdA", "CUAdmin", "nE7jA%5m", "cqunicom",
		"1620@CTCC", "1620@CUcc", "admintelecom", "cuadmin", "lnadmin",
	}, "factory mode auth passwords (comma-separated)")
	rootCmd.PersistentFlags().StringVarP(&ip, "ip", "i", "192.168.1.1", "ONU ip address")
	rootCmd.PersistentFlags().IntVar(&port, "port", 80, "ONU http port")
	rootCmd.PersistentFlags().BoolVar(&telnet, "telnet", false, "permanent telnet (user: root, pass: Zte521) applied by restarting the telnetd service in place, without rebooting; only applied after a temp telnet login is verified")
	rootCmd.PersistentFlags().BoolVar(&telnetRestart, "telnet-restart", false, "permanent telnet (user: root, pass: Zte521) applied by rebooting the device")
	rootCmd.PersistentFlags().IntVar(&telnetPort, "tp", 23, "ONU telnet port")
	rootCmd.PersistentFlags().BoolVar(&newMethod, "new", false, "use the newer time-qualified version61 factory method")
	rootCmd.PersistentFlags().StringVar(&sendInfoProfile, "sendinfo-profile", "rerand34", "method-3 proof profile: rerand34 or rerand22")
	rootCmd.PersistentFlags().StringVar(&iface, "iface", "", "network interface whose MAC to use (default: auto-detected from the route to the ONU)")
	rootCmd.PersistentFlags().StringVarP(&mac, "mac", "m", "", "custom client MAC address for the SendInfo payload (e.g. 00:07:29:55:35:57); overrides --iface and auto-detection")

	telnetCmd := &cobra.Command{
		Use: "telnet [open|close]", Short: "Open or close factory Telnet", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := "open"
			if len(args) == 1 {
				action = args[0]
			}
			if action != "open" && action != "close" {
				return fmt.Errorf("invalid Telnet action %q", action)
			}
			return runTelnet(action)
		},
	}
	serialCmd := &cobra.Command{
		Use: "serial [open|close]", Short: "Enable or disable /proc/serial", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action := "open"
			if len(args) == 1 {
				action = args[0]
			}
			if action != "open" && action != "close" {
				return fmt.Errorf("invalid serial action %q", action)
			}
			return onu.ControlSerial(options(), action)
		},
	}
	rootCmd.AddCommand(telnetCmd, serialCmd)
}

func options() onu.Options {
	return onu.Options{
		Users: users, Passes: passwords, IP: ip, HTTPPort: port, TelnetPort: telnetPort,
		Iface: iface, Mac: mac, NewMethod: newMethod, SendInfoProfile: sendInfoProfile,
	}
}

func runTelnet(action string) error {
	version.Show()

	if telnet && telnetRestart {
		return errors.New("--telnet (in-place restart) and --telnet-restart (reboot) are mutually exclusive")
	}

	if action == "close" {
		return onu.ControlTelnet(options(), action)
	}

	t, _, _, err := onu.OpenTempTelnet(options())
	if err != nil {
		return err
	}
	defer t.Conn.Close()
	fmt.Println("telnet verified, temp factory telnet is open")

	if telnet {
		return onu.SolidifyAndRestart(t, ip, telnetPort)
	}
	if telnetRestart {
		return onu.SolidifyAndReboot(t)
	}
	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
