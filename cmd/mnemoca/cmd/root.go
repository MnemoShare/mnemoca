// Package cmd implements the mnemoca CLI commands (cobra, matching mnemocli
// conventions; ADR-0009).
package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var (
	flagDataDir        string
	flagPassphraseFile string
)

// RootCmd is the mnemoca root command.
var RootCmd = &cobra.Command{
	Use:          "mnemoca",
	Short:        "MnemoCA — a small, post-quantum-ready certificate authority",
	Long:         "MnemoCA is an open-source certificate authority purpose-built for PQC-era\nmachine identity: pure ML-DSA (RFC 9881), classical, and hybrid issuance,\nmulti-tenant, with a hash-chained signed audit log.",
	SilenceUsage: true,
}

func init() {
	RootCmd.PersistentFlags().StringVar(&flagDataDir, "data-dir", defaultDataDir(),
		"CA data directory (default $MNEMOCA_DATA or ./mnemoca-data)")
	RootCmd.PersistentFlags().StringVar(&flagPassphraseFile, "passphrase-file", "",
		"file containing the key-encryption passphrase (default $MNEMOCA_PASSPHRASE)")
}

// Execute runs the CLI.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func defaultDataDir() string {
	if v := os.Getenv("MNEMOCA_DATA"); v != "" {
		return v
	}
	return "./mnemoca-data"
}

// passphrase resolves the softkey passphrase from --passphrase-file or
// $MNEMOCA_PASSPHRASE.
func passphrase() ([]byte, error) {
	if flagPassphraseFile != "" {
		data, err := os.ReadFile(flagPassphraseFile)
		if err != nil {
			return nil, fmt.Errorf("reading passphrase file: %w", err)
		}
		return bytes.TrimSpace(data), nil
	}
	if v := os.Getenv("MNEMOCA_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("no passphrase: set --passphrase-file or $MNEMOCA_PASSPHRASE")
}

// openEnv opens the CA data directory. Callers must Close it.
func openEnv() (*ca.Env, error) {
	pass, err := passphrase()
	if err != nil {
		return nil, err
	}
	env, err := ca.OpenEnv(flagDataDir, pass)
	if err != nil {
		return nil, fmt.Errorf("opening data dir %s: %w", flagDataDir, err)
	}
	return env, nil
}

// cliActor identifies local CLI operations in the audit log.
func cliActor() audit.Actor {
	id := os.Getenv("USER")
	if id == "" {
		id = "cli"
	}
	return audit.Actor{Type: "operator", ID: id}
}

// writeOutput writes data to path with perm, or to stdout when path is empty
// or "-".
func writeOutput(cmd *cobra.Command, path string, data []byte, perm os.FileMode) error {
	if path == "" || path == "-" {
		_, err := cmd.OutOrStdout().Write(data)
		return err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// pf and pln print CLI output; write errors to stdout/stderr are not
// actionable and are deliberately dropped.
func pf(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

func pln(w io.Writer, args ...any) { _, _ = fmt.Fprintln(w, args...) }

// algListHelp renders the registered algorithms for flag help text.
func algListHelp() string {
	algs := pkix.Algorithms()
	slices.Sort(algs)
	out := make([]string, len(algs))
	for i, a := range algs {
		out[i] = string(a)
	}
	return strings.Join(out, ", ")
}
