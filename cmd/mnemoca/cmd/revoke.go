package cmd

import (
	"github.com/spf13/cobra"
)

var (
	revokeTenant string
	revokeSerial string
	revokeReason int
)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke an issued certificate",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		if err := env.Manager.Revoke(cmd.Context(), revokeTenant, revokeSerial, revokeReason, cliActor()); err != nil {
			return err
		}
		pf(cmd.OutOrStdout(), "revoked certificate %s (tenant %s, reason %d)\n",
			revokeSerial, revokeTenant, revokeReason)
		return nil
	},
}

func init() {
	revokeCmd.Flags().StringVar(&revokeTenant, "tenant", "", "tenant ID (required)")
	revokeCmd.Flags().StringVar(&revokeSerial, "serial", "", "certificate serial number (required)")
	revokeCmd.Flags().IntVar(&revokeReason, "reason", 0, "RFC 5280 revocation reason code")
	_ = revokeCmd.MarkFlagRequired("tenant")
	_ = revokeCmd.MarkFlagRequired("serial")
	RootCmd.AddCommand(revokeCmd)
}
