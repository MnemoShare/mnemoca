package cmd

import (
	"net/http"
	"os"
	"strconv"

	"github.com/mnemoshare/mnemoca/internal/acme"
	"github.com/mnemoshare/mnemoca/internal/ca"
)

// acmeHandler builds the RFC 8555 ACME handler mounted under /acme/ by the
// REST API.
func acmeHandler(env *ca.Env, url string, eab bool) http.Handler {
	return acme.New(env.Manager, env.Store, env.Manager.Audit, acme.Options{ExternalURL: url, RequireEAB: eab, AllowPrivateAddresses: acmeAllowPrivate()})
}

// acmeAllowPrivate reads the lab/kind opt-in that lets http-01 validation
// reach non-public addresses.
func acmeAllowPrivate() bool {
	v, _ := strconv.ParseBool(os.Getenv("MNEMOCA_ACME_ALLOW_PRIVATE"))
	return v
}
