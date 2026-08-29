package middleware

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var defaultTrustedProxyCIDRs = []string{
	"127.0.0.0/8",
	"::1",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

var trustedProxyMu sync.RWMutex
var trustedProxyPrefixes = mustParseTrustedProxyPrefixes(defaultTrustedProxyCIDRs)

func mustParseTrustedProxyPrefixes(values []string) []netip.Prefix {
	prefixes, err := parseTrustedProxyPrefixes(values)
	if err != nil {
		panic(err)
	}
	return prefixes
}

func parseTrustedProxyPrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", value, err)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func parseTrustedProxyConfiguration() ([]string, []netip.Prefix, error) {
	rawTrustedProxies := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if rawTrustedProxies == "" {
		log.Print("WARNING: TRUSTED_PROXIES is unset or blank; trusting loopback, RFC 1918, and IPv6 ULA proxy addresses for compatibility. Set TRUSTED_PROXIES=none to trust no proxies, or configure explicit proxy IPs/CIDRs to replace these defaults.")
		trustedProxies := append([]string(nil), defaultTrustedProxyCIDRs...)
		return trustedProxies, mustParseTrustedProxyPrefixes(trustedProxies), nil
	}
	if strings.EqualFold(rawTrustedProxies, "none") {
		return nil, nil, nil
	}

	parts := strings.Split(rawTrustedProxies, ",")
	trustedProxies := make([]string, 0, len(parts))
	for _, part := range parts {
		trustedProxy := strings.TrimSpace(part)
		if trustedProxy == "" {
			continue
		}
		if strings.EqualFold(trustedProxy, "none") {
			return nil, nil, errors.New("TRUSTED_PROXIES=none must be used alone")
		}
		trustedProxies = append(trustedProxies, trustedProxy)
	}
	if len(trustedProxies) == 0 {
		return nil, nil, errors.New("TRUSTED_PROXIES does not contain an IP address or CIDR")
	}
	prefixes, err := parseTrustedProxyPrefixes(trustedProxies)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid TRUSTED_PROXIES: %w", err)
	}
	return trustedProxies, prefixes, nil
}

func setTrustedProxyPrefixes(prefixes []netip.Prefix) {
	trustedProxyMu.Lock()
	trustedProxyPrefixes = append([]netip.Prefix(nil), prefixes...)
	trustedProxyMu.Unlock()
}

func ConfigureTrustedProxies(engine *gin.Engine) error {
	trustedProxies, prefixes, err := parseTrustedProxyConfiguration()
	if err != nil {
		return err
	}
	if err := engine.SetTrustedProxies(trustedProxies); err != nil {
		return fmt.Errorf("invalid TRUSTED_PROXIES: %w", err)
	}
	setTrustedProxyPrefixes(prefixes)
	return nil
}

// IsTrustedProxyRemoteAddr reports whether an HTTP peer address belongs to
// the same immutable proxy set configured for Gin's ClientIP handling.
func IsTrustedProxyRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()
	for _, prefix := range trustedProxyPrefixes {
		if prefix.Contains(addr) || prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}
