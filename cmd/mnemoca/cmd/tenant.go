package cmd

import (
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	tenantCreateName   string
	tenantCreateAlg    string
	tenantCreateHybrid bool
)

var tenantCmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage certificate tenants",
}

var tenantCreateCmd = &cobra.Command{
	Use:   "create <id>",
	Short: "Create a tenant with its issuing CA(s)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		t, err := env.Manager.CreateTenant(cmd.Context(), args[0], tenantCreateName,
			pkix.Algorithm(tenantCreateAlg), tenantCreateHybrid, cliActor())
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		pf(out, "Created tenant %q (%s)\n", t.ID, t.Name)
		pf(out, "  issuing CA: %s\n", t.Alg)
		if t.PairAlg != "" {
			pf(out, "  pair issuing CA: %s\n", t.PairAlg)
		}
		return nil
	},
}

var tenantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tenants",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		tenants, err := env.Manager.ListTenants()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		pln(w, "ID\tNAME\tALG\tPAIR ALG\tCREATED")
		for _, t := range tenants {
			pair := string(t.PairAlg)
			if pair == "" {
				pair = "-"
			}
			pf(w, "%s\t%s\t%s\t%s\t%s\n",
				t.ID, t.Name, t.Alg, pair, t.CreatedAt.Format(time.RFC3339))
		}
		return w.Flush()
	},
}

var tenantShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show a tenant and its issuing certificate(s)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		t, err := env.Manager.GetTenant(args[0])
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		pf(out, "ID:        %s\n", t.ID)
		pf(out, "Name:      %s\n", t.Name)
		pf(out, "Created:   %s\n", t.CreatedAt.Format(time.RFC3339))
		pf(out, "Algorithm: %s\n", t.Alg)
		for name, p := range t.Profiles {
			pf(out, "Profile:   %s (default %s, max %s)\n", name, p.DefaultValidity, p.MaxValidity)
		}
		pf(out, "\nIssuing CA certificate:\n%s", t.CertPEM)
		if t.PairAlg != "" {
			pf(out, "\nPair issuing CA certificate (%s):\n%s", t.PairAlg, t.PairCertPEM)
		}
		return nil
	},
}

func init() {
	tenantCreateCmd.Flags().StringVar(&tenantCreateName, "name", "", "display name (default: the id)")
	tenantCreateCmd.Flags().StringVar(&tenantCreateAlg, "alg", "",
		"issuing CA algorithm (default: inherit the root's; one of "+algListHelp()+")")
	tenantCreateCmd.Flags().BoolVar(&tenantCreateHybrid, "hybrid", false,
		"also create a pair-chain issuing CA (requires a hybrid root)")
	tenantCmd.AddCommand(tenantCreateCmd, tenantListCmd, tenantShowCmd)
	RootCmd.AddCommand(tenantCmd)
}
