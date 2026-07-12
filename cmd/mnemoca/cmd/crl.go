package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	crlTenant string
	crlChain  string
	crlOut    string
)

var crlCmd = &cobra.Command{
	Use:   "crl",
	Short: "Build and sign a fresh CRL for a tenant",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		chain := ca.Chain(crlChain)
		if chain != ca.ChainPrimary && chain != ca.ChainPair {
			return fmt.Errorf("invalid --chain %q (want primary or pair)", crlChain)
		}
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		crl, err := env.Manager.BuildCRL(cmd.Context(), crlTenant, chain, cliActor())
		if err != nil {
			return err
		}
		pf(cmd.ErrOrStderr(), "CRL #%s: %d revoked certificate(s), next update %s\n",
			crl.Number, len(crl.Revoked), crl.NextUpdate.Format("2006-01-02 15:04:05 MST"))
		return writeOutput(cmd, crlOut, pkix.EncodeCRLPEM(crl), 0o644)
	},
}

func init() {
	crlCmd.Flags().StringVar(&crlTenant, "tenant", "", "tenant ID (required)")
	crlCmd.Flags().StringVar(&crlChain, "chain", "primary", "chain to sign the CRL with: primary or pair")
	crlCmd.Flags().StringVarP(&crlOut, "out", "o", "", "output file for the PEM CRL (default stdout)")
	_ = crlCmd.MarkFlagRequired("tenant")
	RootCmd.AddCommand(crlCmd)
}
