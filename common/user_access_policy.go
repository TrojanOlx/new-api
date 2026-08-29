package common

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const MaxUserIPAllowlistEntries = 64

var (
	ErrUserIPAllowlistEmpty        = errors.New("user IP allowlist must contain at least one entry")
	ErrUserIPAllowlistTooLarge     = errors.New("user IP allowlist exceeds the maximum number of entries")
	ErrUserIPAllowlistInvalid      = errors.New("user IP allowlist contains an invalid address")
	ErrUserIPAllowlistUnrestricted = errors.New("user IP allowlist cannot contain an unrestricted network")
)

// NormalizeIPAllowlist canonicalizes IP addresses and prefixes while retaining
// the first-seen order. Empty lines are ignored and duplicate entries collapse.
func NormalizeIPAllowlist(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, rawValue := range values {
		value := strings.TrimSpace(rawValue)
		if value == "" {
			continue
		}

		canonical, err := normalizeIPAllowlistEntry(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		if len(normalized) >= MaxUserIPAllowlistEntries {
			return nil, ErrUserIPAllowlistTooLarge
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

func normalizeIPAllowlistEntry(value string) (string, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return "", fmt.Errorf("%w: %s", ErrUserIPAllowlistUnrestricted, value)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		return prefix.String(), nil
	}

	address, err := netip.ParseAddr(value)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrUserIPAllowlistInvalid, value)
	}
	return address.Unmap().String(), nil
}

// IPAllowlistMatcher is an immutable in-process matcher for a normalized list.
type IPAllowlistMatcher struct {
	prefixes []netip.Prefix
}

func CompileIPAllowlist(values []string) (*IPAllowlistMatcher, error) {
	normalized, err := NormalizeIPAllowlist(values)
	if err != nil {
		return nil, err
	}

	prefixes := make([]netip.Prefix, 0, len(normalized))
	for _, value := range normalized {
		if address, parseErr := netip.ParseAddr(value); parseErr == nil {
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
			continue
		}
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: %s", ErrUserIPAllowlistInvalid, value)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return &IPAllowlistMatcher{prefixes: prefixes}, nil
}

func (matcher *IPAllowlistMatcher) Match(address netip.Addr) bool {
	if matcher == nil || !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range matcher.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
