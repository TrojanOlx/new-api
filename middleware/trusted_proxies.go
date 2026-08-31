package middleware

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
)

var trustedProxyMu sync.RWMutex
var trustedProxyPrefixes []netip.Prefix

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

func setTrustedProxyPrefixes(prefixes []netip.Prefix) {
	trustedProxyMu.Lock()
	trustedProxyPrefixes = append([]netip.Prefix(nil), prefixes...)
	trustedProxyMu.Unlock()
}

func ConfigureTrustedProxies(engine *gin.Engine) error {
	trustedProxies, usedDefaults, err := common.ResolveTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return err
	}
	prefixes, err := parseTrustedProxyPrefixes(trustedProxies)
	if err != nil {
		return err
	}
	if usedDefaults {
		log.Print("WARNING: TRUSTED_PROXIES is unset or blank; trusting loopback, RFC 1918, and IPv6 ULA proxy addresses for compatibility. Set TRUSTED_PROXIES=none to trust no proxies, or configure explicit proxy IPs/CIDRs to replace these defaults.")
	}
	if err := common.ConfigureTrustedProxies(engine, trustedProxies); err != nil {
		return err
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
