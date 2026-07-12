package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	issueTenant       string
	issueCSRFile      string
	issueProfile      string
	issueValidity     string
	issueChain        string
	issueExperimental bool
	issueOut          string
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a certificate from a CSR",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		csrData, err := os.ReadFile(issueCSRFile)
		if err != nil {
			return fmt.Errorf("reading CSR: %w", err)
		}
		csr, err := pkix.ParseCSRPEM(csrData)
		if err != nil {
			return err
		}
		var validity time.Duration
		if issueValidity != "" {
			validity, err = time.ParseDuration(issueValidity)
			if err != nil {
				return fmt.Errorf("invalid --validity: %w", err)
			}
		}

		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		issued, err := env.Manager.Issue(cmd.Context(), ca.IssueRequest{
			Tenant:                issueTenant,
			Profile:               issueProfile,
			CSR:                   csr,
			Validity:              validity,
			Chain:                 ca.Chain(issueChain),
			ExperimentalComposite: issueExperimental,
			Actor:                 cliActor(),
		})
		if err != nil {
			return err
		}

		var out []byte
		for _, iss := range issued {
			out = append(out, pkix.EncodeChainPEM(iss.Path)...)
			pf(cmd.ErrOrStderr(), "issued %s chain certificate serial=%s sig=%s not_after=%s\n",
				iss.Chain, iss.Cert.X509.SerialNumber, iss.Cert.Algorithm,
				iss.Cert.X509.NotAfter.Format(time.RFC3339))
		}
		return writeOutput(cmd, issueOut, out, 0o644)
	},
}

func init() {
	issueCmd.Flags().StringVar(&issueTenant, "tenant", "", "tenant ID (required)")
	issueCmd.Flags().StringVar(&issueCSRFile, "csr", "", "PEM CSR file (required)")
	issueCmd.Flags().StringVar(&issueProfile, "profile", "default", "issuance profile")
	issueCmd.Flags().StringVar(&issueValidity, "validity", "",
		"validity as a Go duration, e.g. 720h (default: the profile's)")
	issueCmd.Flags().StringVar(&issueChain, "chain", "primary", "chain to issue from: primary, pair, or both")
	issueCmd.Flags().BoolVar(&issueExperimental, "experimental-composite", false,
		"allow experimental composite algorithms (draft-19)")
	issueCmd.Flags().StringVarP(&issueOut, "out", "o", "", "output file for leaf+chain PEM (default stdout)")
	_ = issueCmd.MarkFlagRequired("tenant")
	_ = issueCmd.MarkFlagRequired("csr")
	RootCmd.AddCommand(issueCmd)
}
