// Command mnemoca is the open-source MnemoCA CLI (ADR-0009): init, serve,
// tenant, issue, revoke, crl, inspect, keygen, csr, certs, audit, version.
package main

import "github.com/mnemoshare/mnemoca/cmd/mnemoca/cmd"

func main() { cmd.Execute() }
