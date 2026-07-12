package cmd

import (
	"encoding/pem"
	"fmt"

	"github.com/spf13/cobra"

	mldsax509 "filippo.io/mldsa/x509"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	keygenAlg string
	keygenOut string
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a private key (PKCS#8 PEM)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		alg := pkix.Algorithm(keygenAlg)
		info, err := pkix.Lookup(alg)
		if err != nil {
			return err
		}
		if info.Hybrid {
			return fmt.Errorf("composite keys cannot be generated with keygen yet; generate them via CSR tooling")
		}
		key, err := pkix.GenerateKey(alg)
		if err != nil {
			return err
		}
		der, err := mldsax509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		out := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return writeOutput(cmd, keygenOut, out, 0o600)
	},
}

func init() {
	keygenCmd.Flags().StringVar(&keygenAlg, "alg", "", "key algorithm ("+keyAlgListHelp()+") (required)")
	keygenCmd.Flags().StringVarP(&keygenOut, "out", "o", "", "output file (default stdout)")
	_ = keygenCmd.MarkFlagRequired("alg")
	RootCmd.AddCommand(keygenCmd)
}
