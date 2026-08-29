package service

import (
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withDeviceFingerprintSecret(t *testing.T) {
	t.Helper()
	previous := common.DeviceFingerprintSecret
	common.DeviceFingerprintSecret = "device-fingerprint-test-secret-0123456789"
	t.Cleanup(func() { common.DeviceFingerprintSecret = previous })
}

func TestBuildDeviceFingerprintRecognizesCodexDesktopAndIgnoresExactVersion(t *testing.T) {
	withDeviceFingerprintSecret(t)

	base := DeviceRequestMetadata{
		UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
		Originator:        " Codex CLI ",
		CodexInstallation: "install-1",
		StainlessOS:       "windows",
		StainlessArch:     "x86_64",
		StainlessRuntime:  "electron",
		StainlessVersion:  "0.150",
	}
	upgraded := base
	upgraded.UserAgent = "Codex Desktop/0.151 (Windows; x64)"
	upgraded.StainlessVersion = "0.151"

	first, err := BuildDeviceFingerprint(base)
	require.NoError(t, err)
	second, err := BuildDeviceFingerprint(upgraded)
	require.NoError(t, err)

	assert.Equal(t, "Codex Desktop", first.ClientFamily)
	assert.Equal(t, "0.150", first.ClientVersion)
	assert.Equal(t, "Windows", first.OSFamily)
	assert.Equal(t, "amd64", first.Architecture)
	assert.Equal(t, "electron", first.RuntimeFamily)
	assert.Equal(t, "high", first.Confidence)
	assert.NotEmpty(t, first.FingerprintHash)
	assert.Equal(t, first.CompatibilityHash, second.CompatibilityHash)
	assert.Equal(t, first.FingerprintHash, second.FingerprintHash)
}

func TestBuildDeviceFingerprintRecognizesHertzAndCherryStudio(t *testing.T) {
	withDeviceFingerprintSecret(t)

	testCases := []struct {
		name          string
		meta          DeviceRequestMetadata
		clientFamily  string
		clientVersion string
	}{
		{
			name: "hertz",
			meta: DeviceRequestMetadata{
				UserAgent: "hertz/1.2.3 (Linux; arm64)",
			},
			clientFamily:  "hertz",
			clientVersion: "1.2.3",
		},
		{
			name: "cherry studio",
			meta: DeviceRequestMetadata{
				UserAgent: "CherryStudio/1.5.0 (Macintosh; Intel Mac OS X 13_5)",
			},
			clientFamily:  "Cherry Studio",
			clientVersion: "1.5.0",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			evidence, err := BuildDeviceFingerprint(testCase.meta)
			require.NoError(t, err)
			assert.Equal(t, testCase.clientFamily, evidence.ClientFamily)
			assert.Equal(t, testCase.clientVersion, evidence.ClientVersion)
		})
	}
}

func TestBuildDeviceFingerprintUsesStainlessFieldsAndApp(t *testing.T) {
	withDeviceFingerprintSecret(t)

	evidence, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		App:              "Claude Code",
		StainlessOS:      "Darwin",
		StainlessArch:    "arm64",
		StainlessRuntime: "Node",
		StainlessVersion: "1.2.3",
	})
	require.NoError(t, err)

	assert.Equal(t, "Claude Code", evidence.ClientFamily)
	assert.Equal(t, "1.2.3", evidence.ClientVersion)
	assert.Equal(t, "macOS", evidence.OSFamily)
	assert.Equal(t, "arm64", evidence.Architecture)
	assert.Equal(t, "node", evidence.RuntimeFamily)
	assert.Equal(t, "low", evidence.Confidence)
}

func TestBuildDeviceFingerprintDoesNotPersistArbitraryHeaderText(t *testing.T) {
	withDeviceFingerprintSecret(t)

	evidence, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		App:              "private arbitrary app label",
		Originator:       "private arbitrary originator",
		StainlessRuntime: "private arbitrary runtime",
		StainlessVersion: "not a version value",
	})
	require.NoError(t, err)

	assert.Empty(t, evidence.ClientFamily)
	assert.Empty(t, evidence.Originator)
	assert.Empty(t, evidence.RuntimeFamily)
	assert.Empty(t, evidence.ClientVersion)
}

func TestBuildDeviceFingerprintMissingEvidenceIsDeterministicAndLowConfidence(t *testing.T) {
	withDeviceFingerprintSecret(t)

	first, err := BuildDeviceFingerprint(DeviceRequestMetadata{})
	require.NoError(t, err)
	second, err := BuildDeviceFingerprint(DeviceRequestMetadata{})
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.Equal(t, "low", first.Confidence)
	assert.NotEmpty(t, first.FingerprintHash)
	assert.NotEmpty(t, first.CompatibilityHash)
}

func TestBuildDeviceFingerprintOnlyStoresHMACsForSensitiveHints(t *testing.T) {
	withDeviceFingerprintSecret(t)

	evidence, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
		CodexInstallation: "installation-secret-value",
		CodexWindow:       "window-secret-value",
		EdgeJA4:           "ja4-value",
		EdgeHTTP2:         "h2-value",
	})
	require.NoError(t, err)

	assert.NotContains(t, evidence.UserAgentHash, "Codex")
	assert.NotContains(t, evidence.FingerprintHash, "installation-secret-value")
	assert.NotContains(t, evidence.WindowHintHash, "window-secret-value")
	assert.Equal(t, common.GenerateHMACWithKey([]byte("device-window-v1:"+common.DeviceFingerprintSecret), "window-secret-value"), evidence.WindowHintHash)
	assert.NotEmpty(t, evidence.TLSFingerprintHash)
	assert.NotEmpty(t, evidence.HTTP2FingerprintHash)
}

func TestBuildDeviceFingerprintWindowDoesNotChangePermanentHashes(t *testing.T) {
	withDeviceFingerprintSecret(t)

	withoutWindow, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
		CodexInstallation: "installation-1",
	})
	require.NoError(t, err)
	withWindow, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
		CodexInstallation: "installation-1",
		CodexWindow:       "window-1",
	})
	require.NoError(t, err)

	assert.Equal(t, withoutWindow.FingerprintHash, withWindow.FingerprintHash)
	assert.Equal(t, withoutWindow.CompatibilityHash, withWindow.CompatibilityHash)
	assert.NotEqual(t, withoutWindow.WindowHintHash, withWindow.WindowHintHash)
}

func TestBuildDeviceFingerprintEdgeHintsChangeOnlyTechnicalHash(t *testing.T) {
	withDeviceFingerprintSecret(t)

	base := DeviceRequestMetadata{
		UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
		CodexInstallation: "installation-1",
		EdgeJA4:           "ja4-a",
		EdgeHTTP2:         "h2-a",
	}
	changedJA4 := base
	changedJA4.EdgeJA4 = "ja4-b"

	first, err := BuildDeviceFingerprint(base)
	require.NoError(t, err)
	second, err := BuildDeviceFingerprint(changedJA4)
	require.NoError(t, err)

	assert.NotEqual(t, first.FingerprintHash, second.FingerprintHash)
	assert.Equal(t, first.CompatibilityHash, second.CompatibilityHash)
}

func TestBuildDeviceFingerprintTruncatesHeadersByBytesBeforeNormalization(t *testing.T) {
	withDeviceFingerprintSecret(t)

	longASCII := strings.Repeat("a", 200)
	longUnicode := strings.Repeat("界", 100)
	shortASCII := strings.Repeat("a", 128)
	shortUnicode := strings.Repeat("界", 42)

	longEvidence, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		UserAgent:         strings.Repeat("u", 600),
		Originator:        longASCII,
		CodexInstallation: longUnicode,
	})
	require.NoError(t, err)
	shortEvidence, err := BuildDeviceFingerprint(DeviceRequestMetadata{
		UserAgent:         strings.Repeat("u", 512),
		Originator:        shortASCII,
		CodexInstallation: shortUnicode,
	})
	require.NoError(t, err)

	assert.Equal(t, shortEvidence.UserAgentHash, longEvidence.UserAgentHash)
	assert.Equal(t, shortEvidence.FingerprintHash, longEvidence.FingerprintHash)
	assert.Equal(t, shortEvidence.CompatibilityHash, longEvidence.CompatibilityHash)
}

func TestBuildDeviceFingerprintRequiresReadySecret(t *testing.T) {
	previous := common.DeviceFingerprintSecret
	common.DeviceFingerprintSecret = "too-short"
	t.Cleanup(func() { common.DeviceFingerprintSecret = previous })

	_, err := BuildDeviceFingerprint(DeviceRequestMetadata{UserAgent: "Codex Desktop/0.150"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceFingerprintUnavailable)
}
