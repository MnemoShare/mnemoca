package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	profileTenant          string
	profileEKUs            []string
	profileKeyUsages       []string
	profileAllowedAlgs     []string
	profileDefaultValidity time.Duration
	profileMaxValidity     time.Duration
	profileHybrid          string
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage tenant issuance profiles (EKUs, key usages, validity, key algorithms)",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List a tenant's issuance profiles",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		env, err := openEnv(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()
		t, err := env.Manager.GetTenant(cmd.Context(), profileTenant)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "NAME\tEKUS\tKEY USAGES\tDEFAULT\tMAX\tKEY ALGS\tHYBRID")
		for _, p := range t.Profiles {
			ekus := strings.Join(p.EKUs, ",")
			if ekus == "" {
				var legacy []string
				if p.ServerAuth {
					legacy = append(legacy, "server_auth")
				}
				if p.ClientAuth {
					legacy = append(legacy, "client_auth")
				}
				ekus = strings.Join(legacy, ",")
			}
			kus := strings.Join(p.KeyUsages, ",")
			if kus == "" {
				kus = "digital_signature"
			}
			algs := "any"
			if len(p.AllowedKeyAlgs) > 0 {
				strs := make([]string, len(p.AllowedKeyAlgs))
				for i, a := range p.AllowedKeyAlgs {
					strs[i] = string(a)
				}
				algs = strings.Join(strs, ",")
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				p.Name, ekus, kus, p.DefaultValidity, p.MaxValidity, algs, p.Hybrid)
		}
		return w.Flush()
	},
}

var profileSetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Create or replace an issuance profile",
	Long: "Create or replace an issuance profile.\n\n" +
		"EKUs: " + strings.Join(ca.ProfileEKUNames(), ", ") + "\n" +
		"Key usages: " + strings.Join(ca.ProfileKeyUsageNames(), ", ") + "\n\n" +
		"Examples:\n" +
		"  mnemoca profile set mtls-client --tenant prod --eku client_auth --default-validity 720h --max-validity 2160h\n" +
		"  mnemoca profile set sp-signing --tenant prod --eku email_protection --key-usage digital_signature,content_commitment --allowed-key-algs ml-dsa-65",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		env, err := openEnv(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()
		p := ca.Profile{
			Name:            args[0],
			DefaultValidity: profileDefaultValidity,
			MaxValidity:     profileMaxValidity,
			EKUs:            splitList(profileEKUs),
			KeyUsages:       splitList(profileKeyUsages),
			Hybrid:          ca.Chain(profileHybrid),
		}
		for _, a := range splitList(profileAllowedAlgs) {
			p.AllowedKeyAlgs = append(p.AllowedKeyAlgs, pkix.Algorithm(a))
		}
		if err := env.Manager.SetProfile(cmd.Context(), profileTenant, p, cliActor()); err != nil {
			return err
		}
		pf(cmd.OutOrStdout(), "Profile %q set on tenant %q\n", p.Name, profileTenant)
		return nil
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an issuance profile (the default profile cannot be deleted)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		env, err := openEnv(cmd.Context())
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()
		if err := env.Manager.DeleteProfile(cmd.Context(), profileTenant, args[0], cliActor()); err != nil {
			return err
		}
		pf(cmd.OutOrStdout(), "Profile %q deleted from tenant %q\n", args[0], profileTenant)
		return nil
	},
}

// splitList flattens repeated and comma-separated flag values.
func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func init() {
	profileCmd.PersistentFlags().StringVar(&profileTenant, "tenant", "", "tenant ID (required)")
	_ = profileCmd.MarkPersistentFlagRequired("tenant")

	profileSetCmd.Flags().StringSliceVar(&profileEKUs, "eku", nil,
		"extended key usages ("+strings.Join(ca.ProfileEKUNames(), ", ")+")")
	profileSetCmd.Flags().StringSliceVar(&profileKeyUsages, "key-usage", nil,
		"key usages ("+strings.Join(ca.ProfileKeyUsageNames(), ", ")+"; default digital_signature)")
	profileSetCmd.Flags().StringSliceVar(&profileAllowedAlgs, "allowed-key-algs", nil,
		"restrict subject key algorithms (default: any registered)")
	profileSetCmd.Flags().DurationVar(&profileDefaultValidity, "default-validity", 30*24*time.Hour,
		"default certificate validity")
	profileSetCmd.Flags().DurationVar(&profileMaxValidity, "max-validity", 90*24*time.Hour,
		"maximum certificate validity")
	profileSetCmd.Flags().StringVar(&profileHybrid, "hybrid", "",
		"default chain for this profile (primary, pair, both)")

	profileCmd.AddCommand(profileListCmd, profileSetCmd, profileDeleteCmd)
	RootCmd.AddCommand(profileCmd)
}
