package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <cert-or-csr.pem>",
	Short: "Print details of a certificate or CSR (including ML-DSA and composite)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if cert, err := pkix.ParseCertificatePEM(data); err == nil {
			printCertificate(out, cert)
			return nil
		}
		csr, err := pkix.ParseCSRPEM(data)
		if err != nil {
			return fmt.Errorf("%s is neither a certificate nor a CSR PEM", args[0])
		}
		printCSR(out, csr)
		return nil
	},
}

func printCertificate(out io.Writer, cert *pkix.Certificate) {
	pln(out, "Type:                certificate")
	pf(out, "Subject:             %s\n", cert.X509.Subject)
	pf(out, "Issuer:              %s\n", cert.X509.Issuer)
	pf(out, "Serial:              %s\n", cert.X509.SerialNumber)
	pf(out, "Signature algorithm: %s\n", cert.Algorithm)
	pf(out, "Public key:          %s\n", cert.PublicKeyAlgorithm)
	pf(out, "Not before:          %s\n", cert.X509.NotBefore.Format(time.RFC3339))
	pf(out, "Not after:           %s\n", cert.X509.NotAfter.Format(time.RFC3339))
	if cert.X509.IsCA {
		pln(out, "CA:                  true")
	}
	if sans := certSANs(cert); len(sans) > 0 {
		pf(out, "SANs:                %s\n", strings.Join(sans, ", "))
	}
}

func printCSR(out io.Writer, csr *pkix.CertificateRequest) {
	pln(out, "Type:                certificate request")
	pf(out, "Subject:             %s\n", csr.Subject)
	pf(out, "Signature algorithm: %s\n", csr.Algorithm)
	pf(out, "Public key:          %s\n", csr.PublicKeyAlgorithm)
	if sans := csrSANs(csr); len(sans) > 0 {
		pf(out, "SANs:                %s\n", strings.Join(sans, ", "))
	}
}

func certSANs(cert *pkix.Certificate) []string {
	var out []string
	for _, d := range cert.X509.DNSNames {
		out = append(out, "dns:"+d)
	}
	for _, e := range cert.X509.EmailAddresses {
		out = append(out, "email:"+e)
	}
	for _, ip := range cert.X509.IPAddresses {
		out = append(out, "ip:"+ip.String())
	}
	for _, u := range cert.X509.URIs {
		out = append(out, "uri:"+u.String())
	}
	return out
}

func csrSANs(csr *pkix.CertificateRequest) []string {
	var out []string
	for _, d := range csr.DNSNames {
		out = append(out, "dns:"+d)
	}
	for _, e := range csr.EmailAddresses {
		out = append(out, "email:"+e)
	}
	for _, ip := range csr.IPAddresses {
		out = append(out, "ip:"+ip.String())
	}
	for _, u := range csr.URIs {
		out = append(out, "uri:"+u.String())
	}
	return out
}

func init() {
	RootCmd.AddCommand(inspectCmd)
}
