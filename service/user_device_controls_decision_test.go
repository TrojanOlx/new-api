package service

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateUserAPIAccessCarriesResolvedDeviceControls(t *testing.T) {
	user := setupUserAccessPolicyTestDB(t)
	devicePolicyMode := string(constant.UserDevicePolicyObserve)
	require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", user.Id).
		Update("device_policy_mode", devicePolicyMode).Error)
	meta := DeviceRequestMetadata{
		UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
		Originator:        "codex",
		CodexInstallation: "installation-controls",
		StainlessOS:       "windows",
		StainlessArch:     "x86_64",
		StainlessRuntime:  "electron",
		StainlessVersion:  "0.150",
	}
	device, _ := createTrustedUserAccessDevice(t, user, meta, "192.0.2.60", time.Unix(1_700_500_000, 0))
	rpm := 60
	blockedModels := []string{" gpt-5.6-terra ", "gpt-5.6-sol", "gpt-5.6-sol"}
	_, err := model.UpdateUserDeviceWithSnapshot(user.Id, device.Id, model.UserDevicePatch{
		RateLimitRPM:  &rpm,
		BlockedModels: &blockedModels,
	})
	require.NoError(t, err)

	previousBackend := userAccessBackendForAccess
	previousBuilder := buildDeviceFingerprintForAccess
	userAccessBackendForAccess = modelUserAccessBackend{}
	buildDeviceFingerprintForAccess = BuildDeviceFingerprint
	t.Cleanup(func() {
		userAccessBackendForAccess = previousBackend
		buildDeviceFingerprintForAccess = previousBuilder
	})

	base := accessPolicyBaseForTest(t, user.Id)
	result := EvaluateUserAPIAccess(
		base,
		netip.MustParseAddr("192.0.2.60"),
		meta,
		time.Unix(1_700_500_001, 0),
	)
	require.Equal(t, UserAccessAllow, result.Decision)
	assert.Equal(t, device.Id, result.DeviceId)
	assert.NotZero(t, result.FingerprintId)
	assert.Equal(t, 60, result.RateLimitRPM)
	assert.Equal(t, []string{"gpt-5.6-sol", "gpt-5.6-terra"}, result.BlockedModels)
	require.NotNil(t, result.Release)
	result.Release()

	sqlDB, err := model.DB.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	cached := EvaluateUserAPIAccess(
		base,
		netip.MustParseAddr("192.0.2.60"),
		meta,
		time.Unix(1_700_500_002, 0),
	)
	require.Equal(t, UserAccessAllow, cached.Decision)
	assert.Equal(t, device.Id, cached.DeviceId)
	assert.Equal(t, 60, cached.RateLimitRPM)
	assert.Equal(t, []string{"gpt-5.6-sol", "gpt-5.6-terra"}, cached.BlockedModels)
	require.NotNil(t, cached.Release)
	cached.Release()
}

func TestEvaluateUserAPIAccessWithDeviceControlsRejectsOffModeState(t *testing.T) {
	result := EvaluateUserAPIAccess(&model.UserBase{
		Id:                    700,
		APIIPMode:             string(constant.UserIPPolicyUnrestricted),
		APIIPAllowlist:        "[]",
		DevicePolicyMode:      string(constant.UserDevicePolicyOff),
		DeviceControlsEnabled: true,
		AccessPolicyVersion:   1,
	}, netip.MustParseAddr("192.0.2.69"), DeviceRequestMetadata{}, time.Unix(1_700_500_000, 0))

	assert.Equal(t, UserAccessUnavailable, result.Decision)
	assert.Equal(t, "access_control_unavailable", result.Reason)
}

func TestEvaluateUserAPIAccessWithDeviceControlsFailsClosedWhenFingerprintUnavailable(t *testing.T) {
	previousBuilder := buildDeviceFingerprintForAccess
	buildDeviceFingerprintForAccess = func(DeviceRequestMetadata) (DeviceFingerprintEvidence, error) {
		return DeviceFingerprintEvidence{}, ErrDeviceFingerprintUnavailable
	}
	t.Cleanup(func() { buildDeviceFingerprintForAccess = previousBuilder })

	result := EvaluateUserAPIAccess(&model.UserBase{
		Id:                    701,
		APIIPMode:             string(constant.UserIPPolicyUnrestricted),
		APIIPAllowlist:        "[]",
		DevicePolicyMode:      string(constant.UserDevicePolicyObserve),
		DeviceControlsEnabled: true,
		AccessPolicyVersion:   1,
	}, netip.MustParseAddr("192.0.2.70"), DeviceRequestMetadata{}, time.Unix(1_700_500_000, 0))

	assert.Equal(t, UserAccessUnavailable, result.Decision)
	assert.Equal(t, "access_control_unavailable", result.Reason)
}

func TestEvaluateUserAPIAccessWithDeviceControlsFailsClosedWhenDeviceDecisionUnavailable(t *testing.T) {
	backend := &fakeUserAccessBackend{resolveErr: errors.New("device decision store unavailable")}
	useFakeUserAccessBackend(t, backend)

	result := EvaluateUserAPIAccess(&model.UserBase{
		Id:                    702,
		APIIPMode:             string(constant.UserIPPolicyUnrestricted),
		APIIPAllowlist:        "[]",
		DevicePolicyMode:      string(constant.UserDevicePolicyObserve),
		DeviceControlsEnabled: true,
		AccessPolicyVersion:   1,
	}, netip.MustParseAddr("192.0.2.71"), DeviceRequestMetadata{}, time.Unix(1_700_500_000, 0))

	assert.Equal(t, UserAccessUnavailable, result.Decision)
	assert.Equal(t, "access_control_unavailable", result.Reason)
}

func TestEvaluateUserAPIAccessWithDeviceControlsPreservesUntrackedModeSemantics(t *testing.T) {
	backend := &fakeUserAccessBackend{resolution: userDeviceResolution{Untracked: true}}
	useFakeUserAccessBackend(t, backend)

	for _, testCase := range []struct {
		name string
		mode constant.UserDevicePolicyMode
		want UserAccessDecision
	}{
		{name: "observe allows", mode: constant.UserDevicePolicyObserve, want: UserAccessAllow},
		{name: "blacklist allows", mode: constant.UserDevicePolicyBlacklist, want: UserAccessAllow},
		{name: "allowlist denies", mode: constant.UserDevicePolicyAllowlist, want: UserAccessDenyDevice},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := EvaluateUserAPIAccess(&model.UserBase{
				Id:                    703,
				APIIPMode:             string(constant.UserIPPolicyUnrestricted),
				APIIPAllowlist:        "[]",
				DevicePolicyMode:      string(testCase.mode),
				DeviceControlsEnabled: true,
				AccessPolicyVersion:   1,
			}, netip.MustParseAddr("192.0.2.72"), DeviceRequestMetadata{}, time.Unix(1_700_500_000, 0))

			assert.Equal(t, testCase.want, result.Decision)
			assert.NotEqual(t, UserAccessUnavailable, result.Decision)
			if testCase.want == UserAccessDenyDevice {
				assert.Equal(t, "device_untracked", result.Reason)
			}
		})
	}
}

func TestEvaluateUserAPIAccessWithDeviceControlsRejectsCorruptStoredRules(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		updates map[string]interface{}
	}{
		{name: "invalid blocked models", updates: map[string]interface{}{"blocked_models": `{`}},
		{name: "invalid RPM", updates: map[string]interface{}{"rate_limit_rpm": 60_001}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			user := setupUserAccessPolicyTestDB(t)
			meta := DeviceRequestMetadata{
				UserAgent:         "Codex Desktop/0.150 (Windows; x64)",
				CodexInstallation: "installation-corrupt-controls",
				StainlessOS:       "windows",
				StainlessArch:     "x86_64",
				StainlessRuntime:  "electron",
			}
			device, _ := createTrustedUserAccessDevice(t, user, meta, "192.0.2.73", time.Unix(1_700_500_000, 0))
			require.NoError(t, model.DB.Model(&model.UserDevice{}).
				Where("user_id = ? AND id = ?", user.Id, device.Id).Updates(testCase.updates).Error)
			require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", user.Id).Updates(map[string]interface{}{
				"device_policy_mode":      string(constant.UserDevicePolicyObserve),
				"device_controls_enabled": true,
			}).Error)

			result := EvaluateUserAPIAccess(
				accessPolicyBaseForTest(t, user.Id),
				netip.MustParseAddr("192.0.2.73"),
				meta,
				time.Unix(1_700_500_001, 0),
			)

			assert.Equal(t, UserAccessUnavailable, result.Decision)
			assert.Equal(t, "access_control_unavailable", result.Reason)
		})
	}
}
