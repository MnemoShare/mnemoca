package cmd

import (
	"crypto"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	mldsax509 "filippo.io/mldsa/x509"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	csrKeyFile string
	csrCN      string
	csrDNS     []string
	csrEmails  []string
	csrAlg     string
	csrOut     string
)

var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Build a certificate signing request from a private key",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		keyData, err := os.ReadFile(csrKeyFile)
		if err != nil {
			return fmt.Errorf("reading key: %w", err)
		}
		block, _ := pem.Decode(keyData)
		if block == nil || block.Type != "PRIVATE KEY" {
			return fmt.Errorf("no PRIVATE KEY PEM block in %s", csrKeyFile)
		}
		keyAny, err := mldsax509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing key: %w", err)
		}
		key, ok := keyAny.(crypto.Signer)
		if !ok {
			return fmt.Errorf("key type %T cannot sign", keyAny)
		}

		alg := pkix.Algorithm(csrAlg)
		if alg == "" {
			alg, err = pkix.AlgorithmForKey(key.Public())
			if err != nil {
				return err
			}
		}
		csr, err := pkix.CreateCertificateRequest(&x509.CertificateRequest{
			Subject:        stdpkix.Name{CommonName: csrCN},
			DNSNames:       csrDNS,
			EmailAddresses: csrEmails,
		}, key, alg)
		if err != nil {
			return err
		}
		return writeOutput(cmd, csrOut, pkix.EncodeCSRPEM(csr), 0o644)
	},
}

func init() {
	csrCmd.Flags().StringVar(&csrKeyFile, "key", "", "PEM private key file (required)")
	csrCmd.Flags().StringVar(&csrCN, "cn", "", "subject common name (required)")
	csrCmd.Flags().StringSliceVar(&csrDNS, "dns", nil, "DNS SANs (comma-separated or repeated)")
	csrCmd.Flags().StringSliceVar(&csrEmails, "email", nil, "email SANs (comma-separated or repeated)")
	csrCmd.Flags().StringVar(&csrAlg, "alg", "", "signature algorithm (default: inferred from the key)")
	csrCmd.Flags().StringVarP(&csrOut, "out", "o", "", "output file (default stdout)")
	_ = csrCmd.MarkFlagRequired("key")
	_ = csrCmd.MarkFlagRequired("cn")
	RootCmd.AddCommand(csrCmd)
}
