package service

import (
	"testing"

	"github.com/QuantumNous/new-api/constant"
	"github.com/stretchr/testify/assert"
)

func TestUserAccessPolicyModesRejectUnknownValues(t *testing.T) {
	assert.True(t, constant.IsValidUserIPPolicyMode(string(constant.UserIPPolicyAllowlist)))
	assert.True(t, constant.IsValidUserDevicePolicyMode(string(constant.UserDevicePolicyObserve)))
	assert.True(t, constant.IsValidUserDeviceStatus(string(constant.UserDeviceAllowed)))
	assert.True(t, constant.IsValidUserDeviceFingerprintStatus(string(constant.DeviceFingerprintGrace)))
	assert.False(t, constant.IsValidUserIPPolicyMode("sticky"))
	assert.False(t, constant.IsValidUserDevicePolicyMode("enforce"))
	assert.False(t, constant.IsValidUserDeviceStatus("trusted"))
	assert.False(t, constant.IsValidUserDeviceFingerprintStatus("allowed"))
}
