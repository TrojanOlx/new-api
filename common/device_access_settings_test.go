package common

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeIPAllowlistCanonicalizesAndDeduplicatesEntries(t *testing.T) {
	got, err := NormalizeIPAllowlist([]string{
		" ",
		" 192.0.2.10 ",
		"192.0.2.0/24",
		"::ffff:192.0.2.10",
		"::ffff:192.0.2.0/120",
		"2001:0DB8:0000::1",
		"2001:db8::/48",
		"192.0.2.10",
	})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"192.0.2.10",
		"192.0.2.0/24",
		"2001:db8::1",
		"2001:db8::/48",
	}, got)
}

func TestNormalizeIPAllowlistAllowsAnEmptyNormalizedList(t *testing.T) {
	got, err := NormalizeIPAllowlist([]string{"", "  "})

	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestNormalizeIPAllowlistCompilesAnAddressMatcher(t *testing.T) {
	matcher, err := CompileIPAllowlist([]string{"192.0.2.0/24", "2001:db8::10"})

	require.NoError(t, err)
	assert.True(t, matcher.Match(netip.MustParseAddr("192.0.2.42")))
	assert.True(t, matcher.Match(netip.MustParseAddr("2001:db8::10")))
	assert.False(t, matcher.Match(netip.MustParseAddr("198.51.100.1")))
}

func TestNormalizeIPAllowlistRejectsInvalidAndUnboundedEntries(t *testing.T) {
	for _, value := range [][]string{
		{"not-an-ip"},
		{"0.0.0.0/0"},
		{"::/0"},
	} {
		_, err := NormalizeIPAllowlist(value)
		assert.Error(t, err, "expected %v to be rejected", value)
	}

	tooMany := make([]string, 65)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("192.0.2.%d", index+1)
	}
	_, err := NormalizeIPAllowlist(tooMany)
	assert.Error(t, err)
}

func TestInitDeviceAccessSettingsUsesSafeDefaultsAndReadiness(t *testing.T) {
	previousSecret := DeviceFingerprintSecret
	previousGrace := DeviceUpgradeGraceHours
	previousWindow := DeviceActiveNetworkWindowMinutes
	previousRetention := DeviceProfileRetentionDays
	t.Cleanup(func() {
		DeviceFingerprintSecret = previousSecret
		DeviceUpgradeGraceHours = previousGrace
		DeviceActiveNetworkWindowMinutes = previousWindow
		DeviceProfileRetentionDays = previousRetention
	})

	t.Setenv("DEVICE_FINGERPRINT_SECRET", "too-short")
	t.Setenv("DEVICE_UPGRADE_GRACE_HOURS", "73")
	t.Setenv("DEVICE_ACTIVE_NETWORK_WINDOW_MINUTES", "0")
	t.Setenv("DEVICE_PROFILE_RETENTION_DAYS", "29")
	InitDeviceAccessSettings()

	assert.Equal(t, "too-short", DeviceFingerprintSecret)
	assert.Equal(t, DefaultDeviceUpgradeGraceHours, DeviceUpgradeGraceHours)
	assert.Equal(t, DefaultDeviceActiveNetworkWindowMinutes, DeviceActiveNetworkWindowMinutes)
	assert.Equal(t, DefaultDeviceProfileRetentionDays, DeviceProfileRetentionDays)
	assert.False(t, DeviceFingerprintReady())

	t.Setenv("DEVICE_FINGERPRINT_SECRET", "01234567890123456789012345678901")
	t.Setenv("DEVICE_UPGRADE_GRACE_HOURS", "0")
	t.Setenv("DEVICE_ACTIVE_NETWORK_WINDOW_MINUTES", "60")
	t.Setenv("DEVICE_PROFILE_RETENTION_DAYS", "3650")
	InitDeviceAccessSettings()

	assert.Equal(t, 0, DeviceUpgradeGraceHours)
	assert.Equal(t, 60, DeviceActiveNetworkWindowMinutes)
	assert.Equal(t, 3650, DeviceProfileRetentionDays)
	assert.True(t, DeviceFingerprintReady())
}
