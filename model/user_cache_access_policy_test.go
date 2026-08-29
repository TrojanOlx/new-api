package model

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAccessPolicyDefaultsAndUpdatesWithoutChangingAuthVersion(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := User{
		Username:    "policy-defaults",
		Password:    "password",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		AuthVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", user.Id).Update("access_policy_version", 0).Error)
	require.NoError(t, InitializeUserAccessPolicyVersions())

	base, err := GetUserCacheForAccess(user.Id)
	require.NoError(t, err)
	assert.Equal(t, string(constant.UserIPPolicyUnrestricted), base.APIIPMode)
	assert.Equal(t, "[]", base.APIIPAllowlist)
	assert.Equal(t, string(constant.UserDevicePolicyOff), base.DevicePolicyMode)
	assert.EqualValues(t, 1, base.AccessPolicyVersion)

	ipMode := string(constant.UserIPPolicyAllowlist)
	ipAllowlist := `["192.0.2.0/24"]`
	deviceMode := string(constant.UserDevicePolicyObserve)
	updated, changed, err := UpdateUserAccessPolicy(user.Id, UserAccessPolicyPatch{
		IPMode:          &ipMode,
		IPAllowlistJSON: &ipAllowlist,
		DeviceMode:      &deviceMode,
	})
	require.NoError(t, err)
	assert.True(t, changed)
	assert.EqualValues(t, 1, updated.AuthVersion)
	assert.EqualValues(t, 2, updated.AccessPolicyVersion)
	tokenOneUser, err := GetUserCacheForAccess(user.Id)
	require.NoError(t, err)
	tokenTwoUser, err := GetUserCacheForAccess(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 2, tokenOneUser.AccessPolicyVersion)
	assert.EqualValues(t, tokenOneUser.AccessPolicyVersion, tokenTwoUser.AccessPolicyVersion)

	updated, changed, err = UpdateUserAccessPolicy(user.Id, UserAccessPolicyPatch{
		IPMode:          &ipMode,
		IPAllowlistJSON: &ipAllowlist,
		DeviceMode:      &deviceMode,
	})
	require.NoError(t, err)
	assert.False(t, changed)
	assert.EqualValues(t, 2, updated.AccessPolicyVersion)
}

func TestUserAccessPolicyEmptyPatchDoesNotVersionLegacyDefaults(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := User{
		Username:            "policy-legacy-defaults",
		Password:            "password",
		Role:                common.RoleCommonUser,
		Status:              common.UserStatusEnabled,
		Group:               "default",
		AuthVersion:         1,
		APIIPAllowlist:      `["192.0.2.10"]`,
		AccessPolicyVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)

	updated, changed, err := UpdateUserAccessPolicy(user.Id, UserAccessPolicyPatch{})
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, string(constant.UserIPPolicyUnrestricted), updated.APIIPMode)
	assert.Equal(t, string(constant.UserDevicePolicyOff), updated.DevicePolicyMode)
	assert.EqualValues(t, 1, updated.AccessPolicyVersion)
}

func TestUserCacheAccessPolicyFenceRejectsStaleAccessButNotDashboardReads(t *testing.T) {
	truncateTables(t)
	useUserCacheMiniRedis(t)

	user := User{
		Username:            "policy-fence",
		Password:            "password",
		Role:                common.RoleCommonUser,
		Status:              common.UserStatusEnabled,
		Group:               "default",
		AuthVersion:         1,
		AccessPolicyVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, populateUserCache(user))
	require.NoError(t, SetUserAccessPolicyVersionFence(user.Id, 2))

	dashboardUser, err := GetUserCache(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, dashboardUser.AccessPolicyVersion)

	_, err = GetUserCacheForAccess(user.Id)
	assert.ErrorIs(t, err, ErrUserAccessPolicyCachePending)

	err = writeUserCache(user.ToBaseUser(), false)
	assert.ErrorIs(t, err, ErrUserAccessPolicyCachePending)
}

func TestUserAccessPolicyDatabaseFallbackAndProfileUpdateIsolation(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := User{
		Username:            "policy-db-fallback",
		Password:            "password",
		DisplayName:         "before",
		Role:                common.RoleCommonUser,
		Status:              common.UserStatusEnabled,
		Group:               "default",
		AuthVersion:         1,
		AccessPolicyVersion: 1,
	}
	require.NoError(t, DB.Create(&user).Error)
	stale, err := GetUserById(user.Id, false)
	require.NoError(t, err)

	deviceMode := string(constant.UserDevicePolicyBlacklist)
	_, changed, err := UpdateUserAccessPolicy(user.Id, UserAccessPolicyPatch{DeviceMode: &deviceMode})
	require.NoError(t, err)
	require.True(t, changed)

	stale.DisplayName = "after"
	require.NoError(t, stale.Update(false))

	base, err := GetUserCacheForAccess(user.Id)
	require.NoError(t, err)
	assert.Equal(t, string(constant.UserDevicePolicyBlacklist), base.DevicePolicyMode)
	assert.EqualValues(t, 2, base.AccessPolicyVersion)
	assert.EqualValues(t, 1, base.AuthVersion)
}
