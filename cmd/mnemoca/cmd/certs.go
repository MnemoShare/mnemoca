package cmd

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var certsTenant string

var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "List certificates issued to a tenant",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		recs, err := env.Manager.ListCertificates(certsTenant)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		pln(w, "SERIAL\tCN\tKEY ALG\tCHAIN\tEXPIRES\tREVOKED")
		for _, rec := range recs {
			revoked := "no"
			if rec.Revoked {
				revoked = fmt.Sprintf("yes (%s)", rec.RevokedAt.Format(time.RFC3339))
			}
			pf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				rec.Serial, rec.SubjectCN, rec.KeyAlg, rec.Chain,
				rec.NotAfter.Format(time.RFC3339), revoked)
		}
		return w.Flush()
	},
}

func init() {
	certsCmd.Flags().StringVar(&certsTenant, "tenant", "", "tenant ID (required)")
	_ = certsCmd.MarkFlagRequired("tenant")
	RootCmd.AddCommand(certsCmd)
}
