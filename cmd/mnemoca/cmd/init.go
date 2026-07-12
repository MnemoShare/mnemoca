package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	initName         string
	initAlg          string
	initPairAlg      string
	initExperimental bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the CA: root certificate(s) and audit key",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()

		info, err := env.Init(cmd.Context(), ca.InitOptions{
			Name:                  initName,
			Alg:                   pkix.Algorithm(initAlg),
			PairAlg:               pkix.Algorithm(initPairAlg),
			ExperimentalComposite: initExperimental,
			Actor:                 cliActor(),
		})
		if err != nil {
			return err
		}

		rootPath := filepath.Join(env.Dir, "root.pem")
		if err := os.WriteFile(rootPath, info.CertPEM, 0o644); err != nil {
			return fmt.Errorf("writing root certificate: %w", err)
		}
		out := cmd.OutOrStdout()
		pf(out, "Initialized MnemoCA root %q\n", info.Name)
		pf(out, "  primary root:  %-12s %s\n", info.Alg, rootPath)
		if info.PairAlg != "" {
			pairPath := filepath.Join(env.Dir, "root-pair.pem")
			if err := os.WriteFile(pairPath, info.PairCertPEM, 0o644); err != nil {
				return fmt.Errorf("writing pair root certificate: %w", err)
			}
			pf(out, "  pair root:     %-12s %s\n", info.PairAlg, pairPath)
		}
		pf(out, "  audit log:     %s\n", filepath.Join(env.Dir, "audit.log"))
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initName, "name", "", "root CA common name (default \"MnemoCA Root\")")
	initCmd.Flags().StringVar(&initAlg, "alg", string(pkix.MLDSA87),
		"root signature algorithm ("+algListHelp()+")")
	initCmd.Flags().StringVar(&initPairAlg, "pair-alg", "",
		"optional paired root algorithm for parallel-chain hybrid deployments")
	initCmd.Flags().BoolVar(&initExperimental, "experimental-composite", false,
		"allow experimental composite algorithms (draft-19)")
	RootCmd.AddCommand(initCmd)
}
