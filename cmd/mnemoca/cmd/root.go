// Package cmd implements the mnemoca CLI commands (cobra, matching mnemocli
// conventions; ADR-0009).
package cmd

import (
	"bytes"
	"context"
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
	flagDB             string
	flagMongoURI       string
	flagMongoDB        string
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
	RootCmd.PersistentFlags().StringVar(&flagDB, "db", envOr("MNEMOCA_DB", "bolt"),
		"storage backend: bolt (embedded, single node) or mongo (HA) (default $MNEMOCA_DB or bolt)")
	RootCmd.PersistentFlags().StringVar(&flagMongoURI, "mongo-uri", os.Getenv("MNEMOCA_MONGO_URI"),
		"MongoDB connection URI for --db mongo (default $MNEMOCA_MONGO_URI)")
	RootCmd.PersistentFlags().StringVar(&flagMongoDB, "mongo-db", envOr("MNEMOCA_MONGO_DATABASE", "mnemoca"),
		"MongoDB database name for --db mongo (default $MNEMOCA_MONGO_DATABASE or mnemoca)")
}

// envOr returns the environment variable value or a fallback.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Execute runs the CLI.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func defaultDataDir() string { return envOr("MNEMOCA_DATA", "./mnemoca-data") }

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

// openEnv opens the CA environment per the persistent storage flags.
// Callers must Close it.
func openEnv(ctx context.Context) (*ca.Env, error) {
	pass, err := passphrase()
	if err != nil {
		return nil, err
	}
	env, err := ca.OpenEnvConfig(ctx, ca.Config{
		Dir:        flagDataDir,
		Passphrase: pass,
		DB:         flagDB,
		MongoURI:   flagMongoURI,
		MongoDB:    flagMongoDB,
	})
	if err != nil {
		return nil, fmt.Errorf("opening CA environment (%s): %w", flagDB, err)
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

// algListHelp renders the sign-capable algorithms for flag help text.
func algListHelp() string { return joinAlgs(pkix.Algorithms()) }

// keyAlgListHelp renders all subject-key algorithms (adds RSA key-only).
func keyAlgListHelp() string { return joinAlgs(pkix.KeyAlgorithms()) }

func joinAlgs(algs []pkix.Algorithm) string {
	slices.Sort(algs)
	out := make([]string, len(algs))
	for i, a := range algs {
		out[i] = string(a)
	}
	return strings.Join(out, ", ")
}
