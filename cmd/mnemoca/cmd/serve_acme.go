package cmd

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/mnemoshare/mnemoca/internal/acme"
	"github.com/mnemoshare/mnemoca/internal/ca"
)

// acmeHandler builds the RFC 8555 ACME handler mounted under /acme/ by the
// REST API.
func acmeHandler(env *ca.Env, url string, eab bool) (http.Handler, error) {
	allow, err := acmeAllowPrivate()
	if err != nil {
		return nil, err
	}
	return acme.New(env.Manager, env.Store, env.Manager.Audit, acme.Options{ExternalURL: url, RequireEAB: eab, AllowPrivateAddresses: allow}), nil
}

// acmeAllowPrivate reads the lab/kind opt-in that lets http-01 validation
// reach non-public addresses; an unparseable value is a startup error rather
// than a silent default.
func acmeAllowPrivate() (bool, error) {
	v := os.Getenv("MNEMOCA_ACME_ALLOW_PRIVATE")
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("MNEMOCA_ACME_ALLOW_PRIVATE: %q is not a boolean", v)
	}
	return b, nil
}
