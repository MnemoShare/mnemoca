package cmd

import (
	"github.com/spf13/cobra"
)

// Version is the release version, set via -ldflags at build time.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the mnemoca version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		pf(cmd.OutOrStdout(), "mnemoca %s\n", Version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
