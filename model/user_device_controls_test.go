package model

import (
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestUserDeviceControlColumnsMigrate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&User{}, &UserDevice{}))

	assert.True(t, db.Migrator().HasColumn(&User{}, "device_controls_enabled"))
	assert.True(t, db.Migrator().HasColumn(&UserDevice{}, "rate_limit_rpm"))
	assert.True(t, db.Migrator().HasColumn(&UserDevice{}, "blocked_models"))
}

func TestUpdateUserDeviceControlsNormalizesPreservesAndVersions(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-normalize")
	require.NoError(t, DB.Model(user).Update("device_policy_mode", string(constant.UserDevicePolicyObserve)).Error)
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-normalize", time.Now().Unix()))
	require.NoError(t, err)

	rpm := 30
	models := []string{" gpt-5.6-terra ", "gpt-5.6-sol", "gpt-5.6-sol", "", "  "}
	mutation, err := UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{
		RateLimitRPM:  &rpm,
		BlockedModels: &models,
	})
	require.NoError(t, err)
	require.NotNil(t, mutation)
	assert.True(t, mutation.Changed)
	assert.True(t, mutation.ControlsChanged)

	var stored UserDevice
	require.NoError(t, DB.First(&stored, device.Id).Error)
	assert.Equal(t, 30, stored.RateLimitRPM)
	assert.JSONEq(t, `["gpt-5.6-sol","gpt-5.6-terra"]`, stored.BlockedModelsJSON)
	var storedUser User
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.True(t, storedUser.DeviceControlsEnabled)
	assert.EqualValues(t, 2, storedUser.AccessPolicyVersion)

	remark := "preserve controls"
	mutation, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{Remark: &remark})
	require.NoError(t, err)
	assert.True(t, mutation.RemarkChanged)
	assert.False(t, mutation.ControlsChanged)
	require.NoError(t, DB.First(&stored, device.Id).Error)
	assert.Equal(t, 30, stored.RateLimitRPM)
	assert.JSONEq(t, `["gpt-5.6-sol","gpt-5.6-terra"]`, stored.BlockedModelsJSON)
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.EqualValues(t, 2, storedUser.AccessPolicyVersion)

	normalizedModels := []string{"gpt-5.6-sol", "gpt-5.6-terra"}
	mutation, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{
		RateLimitRPM:  &rpm,
		BlockedModels: &normalizedModels,
	})
	require.NoError(t, err)
	assert.False(t, mutation.Changed)
	assert.False(t, mutation.ControlsChanged)

	disabledRPM := 0
	clearedModels := []string{}
	mutation, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{
		RateLimitRPM:  &disabledRPM,
		BlockedModels: &clearedModels,
	})
	require.NoError(t, err)
	assert.True(t, mutation.ControlsChanged)
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.False(t, storedUser.DeviceControlsEnabled)
	assert.EqualValues(t, 3, storedUser.AccessPolicyVersion)
}

func TestUpdateUserDeviceControlsRejectsInvalidValues(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-invalid")
	require.NoError(t, DB.Model(user).Update("device_policy_mode", string(constant.UserDevicePolicyObserve)).Error)
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-invalid", time.Now().Unix()))
	require.NoError(t, err)

	for _, rpm := range []int{-1, 60001} {
		_, err := UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{RateLimitRPM: &rpm})
		assert.ErrorIs(t, err, ErrInvalidUserDeviceRateLimit)
	}
	tooLong := []string{strings.Repeat("m", 129)}
	_, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{BlockedModels: &tooLong})
	assert.ErrorIs(t, err, ErrInvalidUserDeviceBlockedModels)
	tooMany := make([]string, 129)
	for i := range tooMany {
		tooMany[i] = strings.Repeat("m", i/26) + string(rune('a'+i%26))
	}
	_, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{BlockedModels: &tooMany})
	assert.ErrorIs(t, err, ErrInvalidUserDeviceBlockedModels)
}

func TestUserDeviceControlsRequireTrackedDeviceModeAndBlockTurningModeOff(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-mode")
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-mode", time.Now().Unix()))
	require.NoError(t, err)
	rpm := 1
	_, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{RateLimitRPM: &rpm})
	assert.ErrorIs(t, err, ErrUserDeviceControlsRequirePolicy)

	require.NoError(t, DB.Model(user).Update("device_policy_mode", string(constant.UserDevicePolicyObserve)).Error)
	_, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{RateLimitRPM: &rpm})
	require.NoError(t, err)
	off := string(constant.UserDevicePolicyOff)
	_, err = UpdateUserAccessPolicyWithSnapshot(user.Id, UserAccessPolicyPatch{DeviceMode: &off})
	assert.ErrorIs(t, err, ErrUserDeviceControlsMustBeCleared)

	var stored User
	require.NoError(t, DB.First(&stored, user.Id).Error)
	assert.Equal(t, string(constant.UserDevicePolicyObserve), stored.DevicePolicyMode)
	assert.True(t, stored.DeviceControlsEnabled)
}

func TestDevicePolicyCanTurnOffWhenDerivedControlFlagIsStale(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-stale-flag")
	require.NoError(t, DB.Model(user).Updates(map[string]interface{}{
		"device_policy_mode":      string(constant.UserDevicePolicyObserve),
		"device_controls_enabled": true,
	}).Error)
	off := string(constant.UserDevicePolicyOff)
	mutation, err := UpdateUserAccessPolicyWithSnapshot(user.Id, UserAccessPolicyPatch{DeviceMode: &off})
	require.NoError(t, err)
	require.NotNil(t, mutation)
	assert.True(t, mutation.Changed)

	var stored User
	require.NoError(t, DB.First(&stored, user.Id).Error)
	assert.Equal(t, off, stored.DevicePolicyMode)
	assert.False(t, stored.DeviceControlsEnabled)
}

func TestStalePendingDeviceCleanupKeepsConfiguredControls(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-cleanup")
	require.NoError(t, DB.Model(user).Update("device_policy_mode", string(constant.UserDevicePolicyObserve)).Error)
	seenAt := time.Now().Add(-91 * 24 * time.Hour).Unix()
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-cleanup", seenAt))
	require.NoError(t, err)
	rpm := 10
	_, err = UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{RateLimitRPM: &rpm})
	require.NoError(t, err)

	require.NoError(t, DeleteStalePendingUserDevices(time.Now().Add(-90*24*time.Hour).Unix()))
	var stored UserDevice
	require.NoError(t, DB.First(&stored, device.Id).Error)
	assert.Equal(t, 10, stored.RateLimitRPM)
}

func TestOrdinaryUserUpdateCannotOverwriteDeviceControlsFlag(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-profile-isolation")
	stale, err := GetUserById(user.Id, false)
	require.NoError(t, err)
	stale.DeviceControlsEnabled = true
	stale.DisplayName = "updated profile"
	require.NoError(t, stale.Update(false))

	var stored User
	require.NoError(t, DB.First(&stored, user.Id).Error)
	assert.False(t, stored.DeviceControlsEnabled)
}

func TestDeviceControlsFlagPublishesInCacheSchemaFour(t *testing.T) {
	truncateTables(t)
	useUserCacheMiniRedis(t)

	user := User{
		Username: "device-controls-cache", Password: "password", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1,
		AccessPolicyVersion: 2, DevicePolicyMode: string(constant.UserDevicePolicyObserve),
		DeviceControlsEnabled: true,
	}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, populateUserCache(user))

	cached, err := GetUserCacheForAccess(user.Id)
	require.NoError(t, err)
	assert.True(t, cached.DeviceControlsEnabled)
	assert.Equal(t, 4, cached.CacheSchema)
}

func TestInitializeUserDeviceControlsBackfillsLegacyNullDefaults(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-legacy-null")
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-legacy-null", time.Now().Unix()))
	require.NoError(t, err)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", user.Id).UpdateColumn("device_controls_enabled", nil).Error)
	require.NoError(t, DB.Model(&UserDevice{}).Where("id = ?", device.Id).Updates(map[string]interface{}{
		"rate_limit_rpm": nil,
		"blocked_models": nil,
	}).Error)

	require.NoError(t, InitializeUserDeviceControls())
	require.NoError(t, InitializeUserDeviceControls())

	var nullUserFlags int64
	require.NoError(t, DB.Model(&User{}).
		Where("id = ? AND device_controls_enabled IS NULL", user.Id).
		Count(&nullUserFlags).Error)
	assert.Zero(t, nullUserFlags)
	var nullRateLimits int64
	require.NoError(t, DB.Model(&UserDevice{}).
		Where("id = ? AND rate_limit_rpm IS NULL", device.Id).
		Count(&nullRateLimits).Error)
	assert.Zero(t, nullRateLimits)

	var storedUser User
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.False(t, storedUser.DeviceControlsEnabled)
	var storedDevice UserDevice
	require.NoError(t, DB.First(&storedDevice, device.Id).Error)
	assert.Zero(t, storedDevice.RateLimitRPM)
	assert.Equal(t, "[]", storedDevice.BlockedModelsJSON)
}

func TestInitializeUserDeviceControlsBackfillsCanonicalStateIdempotently(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })

	user := createDeviceTestUser(t, "device-controls-initialize")
	require.NoError(t, DB.Model(user).Update("device_policy_mode", string(constant.UserDevicePolicyObserve)).Error)
	controlled, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-initialize-active", time.Now().Unix()))
	require.NoError(t, err)
	empty, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-controls-initialize-empty", time.Now().Unix()))
	require.NoError(t, err)
	require.NoError(t, DB.Model(&UserDevice{}).Where("id = ?", controlled.Id).Update("blocked_models", `[" gpt-5.6-terra ","gpt-5.6-sol","gpt-5.6-sol"]`).Error)
	require.NoError(t, DB.Model(&UserDevice{}).Where("id = ?", empty.Id).Update("blocked_models", "").Error)
	require.NoError(t, DB.Model(&User{}).Where("id = ?", user.Id).Update("device_controls_enabled", false).Error)

	require.NoError(t, InitializeUserDeviceControls())
	require.NoError(t, InitializeUserDeviceControls())

	var storedUser User
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.True(t, storedUser.DeviceControlsEnabled)
	var storedControlled UserDevice
	require.NoError(t, DB.First(&storedControlled, controlled.Id).Error)
	assert.JSONEq(t, `["gpt-5.6-sol","gpt-5.6-terra"]`, storedControlled.BlockedModelsJSON)
	var storedEmpty UserDevice
	require.NoError(t, DB.First(&storedEmpty, empty.Id).Error)
	assert.Equal(t, "[]", storedEmpty.BlockedModelsJSON)
}
