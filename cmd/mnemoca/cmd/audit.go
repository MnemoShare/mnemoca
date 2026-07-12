package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var auditLogPath string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the audit log's hash chain and signatures",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		info, err := env.Manager.Root()
		if err != nil {
			return err
		}
		pub, err := pkix.ParsePublicKeyPEM(info.AuditPubPEM)
		if err != nil {
			return fmt.Errorf("parsing audit public key: %w", err)
		}
		path := auditLogPath
		if path == "" {
			path = filepath.Join(env.Dir, "audit.log")
		}
		n, err := audit.Verify(path, pub)
		if err != nil {
			return fmt.Errorf("after %d valid record(s): %w", n, err)
		}
		pf(cmd.OutOrStdout(), "audit chain OK: %d record(s) verified\n", n)
		return nil
	},
}

func init() {
	auditVerifyCmd.Flags().StringVar(&auditLogPath, "log", "",
		"audit log path (default <data-dir>/audit.log)")
	auditCmd.AddCommand(auditVerifyCmd)
	RootCmd.AddCommand(auditCmd)
}
