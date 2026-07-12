package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/api"
)

var (
	serveListen      string
	serveExternalURL string
	serveACMEEAB     bool
	serveTLSCert     string
	serveTLSKey      string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the MnemoCA REST + ACME server",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if (serveTLSCert == "") != (serveTLSKey == "") {
			return fmt.Errorf("--tls-cert and --tls-key must be set together")
		}
		env, err := openEnv()
		if err != nil {
			return err
		}
		defer func() { _ = env.Close() }()
		if env.AuditLog == nil {
			return fmt.Errorf("CA not initialized (run `mnemoca init`)")
		}

		handler := api.New(env, api.Options{
			ExternalURL: serveExternalURL,
			ACME:        acmeHandler(env, serveExternalURL, serveACMEEAB),
		})
		srv := &http.Server{
			Addr:              serveListen,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		errCh := make(chan error, 1)
		go func() {
			if serveTLSCert != "" {
				errCh <- srv.ListenAndServeTLS(serveTLSCert, serveTLSKey)
			} else {
				errCh <- srv.ListenAndServe()
			}
		}()
		scheme := "http"
		if serveTLSCert != "" {
			scheme = "https"
		}
		pf(cmd.ErrOrStderr(), "mnemoca: serving %s on %s\n", scheme, serveListen)

		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
		}
		pln(cmd.ErrOrStderr(), "mnemoca: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveListen, "listen", ":8443", "listen address")
	serveCmd.Flags().StringVar(&serveExternalURL, "external-url", "",
		"base URL clients reach this server at (used in ACME directory URLs)")
	serveCmd.Flags().BoolVar(&serveACMEEAB, "acme-eab", false,
		"require ACME External Account Binding (tenant-scoped enrollment)")
	serveCmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "TLS certificate file (plain HTTP if unset)")
	serveCmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "TLS private key file")
	RootCmd.AddCommand(serveCmd)
}
