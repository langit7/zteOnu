package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/septrum101/zteOnu/app/hardcode"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "hardcode ROOT_KEY CONFIG [CONFIG...]",
		Short: "Decrypt ZTE /etc/hardcodefile containers",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read hardcode root key: %w", err)
			}
			if line := bytes.IndexByte(root, '\n'); line >= 0 {
				root = root[:line]
			}
			root = bytes.TrimSpace(root)
			for _, name := range args[1:] {
				if err := decryptHardcodeFile(root, name); err != nil {
					return err
				}
			}
			return nil
		},
	})
}

func decryptHardcodeFile(root []byte, name string) error {
	source, err := os.Open(name)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	plain, decryptErr := hardcode.Decrypt(root, source)
	closeErr := source.Close()
	if decryptErr != nil {
		if strings.Contains(decryptErr.Error(), "not a ZTE") {
			fmt.Printf("%s is not a hardcode config file, skip\n", name)
			return nil
		}
		return fmt.Errorf("decrypt %s: %w", name, decryptErr)
	}
	if closeErr != nil {
		return closeErr
	}
	destination := filepath.Clean(name) + ".txt"
	if err := os.WriteFile(destination, plain, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", destination, err)
	}
	fmt.Printf("decrypted %s -> %s\n", name, destination)
	return nil
}
