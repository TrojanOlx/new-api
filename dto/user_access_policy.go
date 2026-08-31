package dto

type UserAccessPolicyUpdateRequest struct {
	IPMode      *string   `json:"ip_mode"`
	IPAllowlist *[]string `json:"ip_allowlist"`
	DeviceMode  *string   `json:"device_mode"`
}

type UserAccessPolicyResponse struct {
	UserId                     int      `json:"user_id"`
	IPMode                     string   `json:"ip_mode"`
	IPAllowlist                []string `json:"ip_allowlist"`
	DeviceMode                 string   `json:"device_mode"`
	AccessPolicyVersion        int64    `json:"access_policy_version"`
	FingerprintReady           bool     `json:"fingerprint_ready"`
	UpgradeGraceHours          int      `json:"upgrade_grace_hours"`
	ActiveNetworkWindowMinutes int      `json:"active_network_window_minutes"`
}

type UserDeviceUpdateRequest struct {
	Status        *string   `json:"status"`
	Remark        *string   `json:"remark"`
	RateLimitRPM  *int      `json:"rate_limit_rpm"`
	BlockedModels *[]string `json:"blocked_models"`
}

type UserDeviceFingerprintUpdateRequest struct {
	Status *string `json:"status"`
}
