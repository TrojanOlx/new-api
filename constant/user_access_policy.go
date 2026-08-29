package constant

// UserIPPolicyMode controls the user-level IP policy applied to API tokens.
type UserIPPolicyMode string

// UserDevicePolicyMode controls how device observations are handled.
type UserDevicePolicyMode string

// UserDeviceStatus is the status of a logical device.
type UserDeviceStatus string

// UserDeviceFingerprintStatus is the status of one technical fingerprint alias.
type UserDeviceFingerprintStatus string

const (
	UserIPPolicyUnrestricted UserIPPolicyMode = "unrestricted"
	UserIPPolicyAllowlist    UserIPPolicyMode = "allowlist"

	UserDevicePolicyOff       UserDevicePolicyMode = "off"
	UserDevicePolicyObserve   UserDevicePolicyMode = "observe"
	UserDevicePolicyAllowlist UserDevicePolicyMode = "allowlist"
	UserDevicePolicyBlacklist UserDevicePolicyMode = "blacklist"

	UserDevicePending UserDeviceStatus = "pending"
	UserDeviceAllowed UserDeviceStatus = "allowed"
	UserDeviceBlocked UserDeviceStatus = "blocked"

	DeviceFingerprintPending UserDeviceFingerprintStatus = "pending"
	DeviceFingerprintTrusted UserDeviceFingerprintStatus = "trusted"
	DeviceFingerprintGrace   UserDeviceFingerprintStatus = "grace"
	DeviceFingerprintBlocked UserDeviceFingerprintStatus = "blocked"
)

func IsValidUserIPPolicyMode(mode string) bool {
	switch UserIPPolicyMode(mode) {
	case UserIPPolicyUnrestricted, UserIPPolicyAllowlist:
		return true
	default:
		return false
	}
}

func IsValidUserDevicePolicyMode(mode string) bool {
	switch UserDevicePolicyMode(mode) {
	case UserDevicePolicyOff, UserDevicePolicyObserve, UserDevicePolicyAllowlist, UserDevicePolicyBlacklist:
		return true
	default:
		return false
	}
}

func IsValidUserDeviceStatus(status string) bool {
	switch UserDeviceStatus(status) {
	case UserDevicePending, UserDeviceAllowed, UserDeviceBlocked:
		return true
	default:
		return false
	}
}

func IsValidUserDeviceFingerprintStatus(status string) bool {
	switch UserDeviceFingerprintStatus(status) {
	case DeviceFingerprintPending, DeviceFingerprintTrusted, DeviceFingerprintGrace, DeviceFingerprintBlocked:
		return true
	default:
		return false
	}
}
