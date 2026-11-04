package acme

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

const challengeTimeout = 10 * time.Second

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "fd00:ec2::254/128",
	} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// blockedAddress reports whether ip is a destination the CA must not dial for
// http-01 validation.
func blockedAddress(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// safeDialControl is a net.Dialer Control hook: it runs after DNS resolution
// on the address actually being connected to, so a name that re-resolves to
// an internal address between check and use (rebinding) is still refused.
func safeDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("acme: dial to %q not permitted: %w", address, err)
	}
	if blockedAddress(net.ParseIP(host)) {
		return fmt.Errorf("acme: dial to %s not permitted: non-public address", host)
	}
	return nil
}

// newChallengeClient builds the http-01 client. Proxies are never used, and
// every connection (including redirect hops) goes through the dial guard
// unless private addresses are explicitly allowed.
func newChallengeClient(allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: challengeTimeout}
	if !allowPrivate {
		d.Control = safeDialControl
	}
	return &http.Client{
		Timeout:   challengeTimeout,
		Transport: &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true},
	}
}
