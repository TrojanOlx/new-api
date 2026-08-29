package service

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
)

const (
	deviceUserAgentMaxBytes = 512
	deviceHeaderMaxBytes    = 128
)

var ErrDeviceFingerprintUnavailable = errors.New("device fingerprint secret is unavailable")

type DeviceRequestMetadata struct {
	UserAgent         string
	Originator        string
	CodexInstallation string
	CodexWindow       string
	StainlessOS       string
	StainlessArch     string
	StainlessRuntime  string
	StainlessVersion  string
	App               string
	EdgeJA4           string
	EdgeHTTP2         string
}

type DeviceFingerprintEvidence struct {
	FingerprintHash      string
	CompatibilityHash    string
	ClientFamily         string
	ClientVersion        string
	OSFamily             string
	Architecture         string
	Originator           string
	RuntimeFamily        string
	UserAgentHash        string
	WindowHintHash       string
	TLSFingerprintHash   string
	HTTP2FingerprintHash string
	Confidence           string
}

func truncateDeviceHeader(value string, maxBytes int) string {
	if len(value) > maxBytes {
		value = value[:maxBytes]
		for value != "" && !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(value), " "))
}

func truncateDeviceValue(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for value != "" && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func normalizeDeviceApp(value string) string {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "claude code"), strings.Contains(value, "claude-code"):
		return "Claude Code"
	case strings.Contains(value, "codex desktop"):
		return "Codex Desktop"
	case strings.Contains(value, "codex"):
		return "Codex CLI"
	case strings.Contains(value, "cherry"):
		return "Cherry Studio"
	case strings.Contains(value, "trae"):
		return "Trae"
	default:
		return ""
	}
}

func normalizeDeviceOriginator(value string) string {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "codex"):
		return "codex"
	case strings.Contains(value, "claude"):
		return "claude"
	case strings.Contains(value, "cherry"):
		return "cherry"
	case strings.Contains(value, "trae"):
		return "trae"
	case strings.Contains(value, "openai"):
		return "openai"
	case strings.Contains(value, "anthropic"):
		return "anthropic"
	default:
		return ""
	}
}

func normalizeDeviceRuntime(value string) string {
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "electron"):
		return "electron"
	case strings.Contains(value, "node"):
		return "node"
	case strings.Contains(value, "deno"):
		return "deno"
	case strings.Contains(value, "bun"):
		return "bun"
	case strings.Contains(value, "python"):
		return "python"
	case strings.Contains(value, "ruby"):
		return "ruby"
	case value == "go", strings.HasPrefix(value, "go/"):
		return "go"
	case strings.Contains(value, "rust"):
		return "rust"
	case strings.Contains(value, "java"):
		return "java"
	default:
		return ""
	}
}

func normalizeDeviceVersion(value string) string {
	value = truncateDeviceValue(value, 64)
	hasDigit := false
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char == '.', char == '-', char == '_', char == '+':
		default:
			return ""
		}
	}
	if !hasDigit {
		return ""
	}
	return value
}

func parseDeviceClient(userAgent, app, originator string) (string, string) {
	lowerUserAgent := strings.ToLower(userAgent)
	clientPatterns := []struct {
		prefix string
		family string
	}{
		{prefix: "codex desktop/", family: "Codex Desktop"},
		{prefix: "codex_cli_rs/", family: "Codex CLI"},
		{prefix: "codex/", family: "Codex CLI"},
		{prefix: "cherrystudio/", family: "Cherry Studio"},
		{prefix: "cherry studio/", family: "Cherry Studio"},
		{prefix: "trae/", family: "Trae"},
		{prefix: "hertz/", family: "hertz"},
	}
	for _, pattern := range clientPatterns {
		index := strings.Index(lowerUserAgent, pattern.prefix)
		if index < 0 {
			continue
		}
		versionStart := index + len(pattern.prefix)
		versionEnd := versionStart
		for versionEnd < len(userAgent) && !strings.ContainsRune(" \t;()", rune(userAgent[versionEnd])) {
			versionEnd++
		}
		return pattern.family, normalizeDeviceVersion(userAgent[versionStart:versionEnd])
	}
	if app != "" {
		return truncateDeviceValue(app, 64), ""
	}
	lowerOriginator := strings.ToLower(originator)
	switch {
	case strings.Contains(lowerOriginator, "codex"):
		return "Codex CLI", ""
	case strings.Contains(lowerOriginator, "cherry"):
		return "Cherry Studio", ""
	case strings.Contains(lowerOriginator, "trae"):
		return "Trae", ""
	default:
		return "", ""
	}
}

func normalizeDeviceOS(stainlessOS, userAgent string) string {
	value := strings.ToLower(stainlessOS + " " + userAgent)
	switch {
	case strings.Contains(value, "windows"):
		return "Windows"
	case strings.Contains(value, "darwin"), strings.Contains(value, "macintosh"), strings.Contains(value, "mac os"):
		return "macOS"
	case strings.Contains(value, "linux"):
		return "Linux"
	case strings.Contains(value, "android"):
		return "Android"
	case strings.Contains(value, "ios"):
		return "iOS"
	default:
		return ""
	}
}

func normalizeDeviceArchitecture(stainlessArch, userAgent string) string {
	value := strings.ToLower(stainlessArch + " " + userAgent)
	switch {
	case strings.Contains(value, "aarch64"), strings.Contains(value, "arm64"):
		return "arm64"
	case strings.Contains(value, "x86_64"), strings.Contains(value, "x64"), strings.Contains(value, "amd64"):
		return "amd64"
	case strings.Contains(value, "i386"), strings.Contains(value, "i686"), strings.Contains(value, "x86"):
		return "386"
	case strings.Contains(value, "arm"):
		return "arm"
	default:
		return ""
	}
}

func BuildDeviceFingerprint(meta DeviceRequestMetadata) (DeviceFingerprintEvidence, error) {
	if !common.DeviceFingerprintReady() {
		return DeviceFingerprintEvidence{}, ErrDeviceFingerprintUnavailable
	}

	userAgent := truncateDeviceHeader(meta.UserAgent, deviceUserAgentMaxBytes)
	originator := normalizeDeviceOriginator(truncateDeviceHeader(meta.Originator, deviceHeaderMaxBytes))
	installation := truncateDeviceHeader(meta.CodexInstallation, deviceHeaderMaxBytes)
	window := truncateDeviceHeader(meta.CodexWindow, deviceHeaderMaxBytes)
	stainlessOS := truncateDeviceHeader(meta.StainlessOS, deviceHeaderMaxBytes)
	stainlessArch := truncateDeviceHeader(meta.StainlessArch, deviceHeaderMaxBytes)
	stainlessRuntime := normalizeDeviceRuntime(truncateDeviceHeader(meta.StainlessRuntime, deviceHeaderMaxBytes))
	stainlessVersion := truncateDeviceHeader(meta.StainlessVersion, deviceHeaderMaxBytes)
	app := normalizeDeviceApp(truncateDeviceHeader(meta.App, deviceHeaderMaxBytes))
	edgeJA4 := truncateDeviceHeader(meta.EdgeJA4, deviceHeaderMaxBytes)
	edgeHTTP2 := truncateDeviceHeader(meta.EdgeHTTP2, deviceHeaderMaxBytes)

	clientFamily, clientVersion := parseDeviceClient(userAgent, app, originator)
	if stainlessVersion != "" {
		clientVersion = normalizeDeviceVersion(stainlessVersion)
	}
	osFamily := normalizeDeviceOS(stainlessOS, userAgent)
	architecture := normalizeDeviceArchitecture(stainlessArch, userAgent)
	runtimeFamily := stainlessRuntime
	normalizedOriginator := originator

	secret := common.DeviceFingerprintSecret
	installationHash := ""
	if installation != "" {
		installationHash = common.GenerateHMACWithKey([]byte("device-installation-v1:"+secret), installation)
	}
	userAgentHash := ""
	if userAgent != "" {
		userAgentHash = common.GenerateHMACWithKey([]byte("device-user-agent-v1:"+secret), userAgent)
	}
	windowHintHash := ""
	if window != "" {
		windowHintHash = common.GenerateHMACWithKey([]byte("device-window-v1:"+secret), window)
	}
	tlsFingerprintHash := ""
	if edgeJA4 != "" {
		tlsFingerprintHash = common.GenerateHMACWithKey([]byte("device-edge-ja4-v1:"+secret), edgeJA4)
	}
	http2FingerprintHash := ""
	if edgeHTTP2 != "" {
		http2FingerprintHash = common.GenerateHMACWithKey([]byte("device-edge-h2-v1:"+secret), edgeHTTP2)
	}

	profileMaterial := strings.Join([]string{
		strings.ToLower(clientFamily),
		strings.ToLower(osFamily),
		strings.ToLower(architecture),
		normalizedOriginator,
		runtimeFamily,
		installationHash,
		tlsFingerprintHash,
		http2FingerprintHash,
	}, "\n")
	compatibilityMaterial := strings.Join([]string{
		strings.ToLower(clientFamily),
		strings.ToLower(osFamily),
		strings.ToLower(architecture),
		normalizedOriginator,
		runtimeFamily,
		installationHash,
	}, "\n")

	confidence := "low"
	if installationHash != "" || (tlsFingerprintHash != "" && http2FingerprintHash != "") {
		confidence = "high"
	} else if clientFamily != "" && (osFamily != "" || architecture != "") &&
		(tlsFingerprintHash != "" || http2FingerprintHash != "" || normalizedOriginator != "") {
		confidence = "medium"
	}

	return DeviceFingerprintEvidence{
		FingerprintHash:      common.GenerateHMACWithKey([]byte("device-profile-v1:"+secret), profileMaterial),
		CompatibilityHash:    common.GenerateHMACWithKey([]byte("device-compat-v1:"+secret), compatibilityMaterial),
		ClientFamily:         clientFamily,
		ClientVersion:        clientVersion,
		OSFamily:             osFamily,
		Architecture:         architecture,
		Originator:           normalizedOriginator,
		RuntimeFamily:        runtimeFamily,
		UserAgentHash:        userAgentHash,
		WindowHintHash:       windowHintHash,
		TLSFingerprintHash:   tlsFingerprintHash,
		HTTP2FingerprintHash: http2FingerprintHash,
		Confidence:           confidence,
	}, nil
}
