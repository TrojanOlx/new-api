package model

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func deviceTestHash(prefix string) string {
	if len(prefix) >= 64 {
		return prefix[:64]
	}
	return prefix + strings.Repeat("0", 64-len(prefix))
}

func TestUpdateUserDeviceRetriesCachePublishAfterCommittedFailure(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })
	user := createDeviceTestUser(t, "device-publish-retry")
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-publish-retry", time.Now().Unix()))
	require.NoError(t, err)
	previousPublish := publishUserAccessPolicyCacheForMutation
	publishCalls := 0
	publishUserAccessPolicyCacheForMutation = func(int) error {
		publishCalls++
		if publishCalls == 1 {
			return errors.New("cache unavailable")
		}
		return nil
	}
	t.Cleanup(func() { publishUserAccessPolicyCacheForMutation = previousPublish })

	blocked := string(constant.UserDeviceBlocked)
	err = UpdateUserDevice(user.Id, device.Id, UserDevicePatch{Status: &blocked})
	assert.ErrorIs(t, err, ErrUserAccessPolicyCachePublish)
	var stored UserDevice
	require.NoError(t, DB.First(&stored, device.Id).Error)
	assert.Equal(t, blocked, stored.Status)

	require.NoError(t, UpdateUserDevice(user.Id, device.Id, UserDevicePatch{Status: &blocked}))
	assert.Equal(t, 2, publishCalls)
}

func TestUpdateUserDeviceWithSnapshotReturnsLockedBeforeAfterAndChanged(t *testing.T) {
	truncateTables(t)
	oldRedisEnabled := common.RedisEnabled
	common.RedisEnabled = false
	t.Cleanup(func() { common.RedisEnabled = oldRedisEnabled })
	user := createDeviceTestUser(t, "device-snapshot")
	device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "snapshot", time.Now().Unix()))
	require.NoError(t, err)

	allowed := string(constant.UserDeviceAllowed)
	mutation, err := UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{Status: &allowed})
	require.NoError(t, err)
	require.NotNil(t, mutation)
	assert.True(t, mutation.Changed)
	assert.Equal(t, string(constant.UserDevicePending), mutation.Before.Status)
	assert.Equal(t, allowed, mutation.After.Status)

	noOp, err := UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{Status: &allowed})
	require.NoError(t, err)
	require.NotNil(t, noOp)
	assert.False(t, noOp.Changed)
	assert.Equal(t, noOp.Before.Status, noOp.After.Status)
	assert.Equal(t, noOp.Before.Remark, noOp.After.Remark)

	// The first device transition above intentionally auto-trusts its pending
	// alias. Use a fresh device to exercise an actual administrator alias
	// transition and its locked before/after snapshot.
	secondDevice, secondFingerprint, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "snapshot-alias", time.Now().Unix()))
	require.NoError(t, err)
	fingerprintStatus, err := UpdateUserDeviceFingerprintWithSnapshot(user.Id, secondDevice.Id, secondFingerprint.Id, string(constant.DeviceFingerprintTrusted))
	require.NoError(t, err)
	require.NotNil(t, fingerprintStatus)
	assert.True(t, fingerprintStatus.Changed)
	assert.Equal(t, string(constant.DeviceFingerprintTrusted), fingerprintStatus.After.Status)
	assert.Equal(t, secondFingerprint.ShortId, fingerprintStatus.Before.ShortId)

	fingerprintNoOp, err := UpdateUserDeviceFingerprintWithSnapshot(user.Id, secondDevice.Id, secondFingerprint.Id, string(constant.DeviceFingerprintTrusted))
	require.NoError(t, err)
	require.NotNil(t, fingerprintNoOp)
	assert.False(t, fingerprintNoOp.Changed)
	assert.Equal(t, fingerprintNoOp.Before.Status, fingerprintNoOp.After.Status)
}

func createDeviceTestUser(t *testing.T, username string) *User {
	t.Helper()
	user := &User{
		Username:            username,
		Password:            "password",
		Role:                common.RoleCommonUser,
		Status:              common.UserStatusEnabled,
		Group:               "default",
		AffCode:             username,
		AuthVersion:         1,
		AccessPolicyVersion: 1,
	}
	require.NoError(t, DB.Create(user).Error)
	return user
}

func observedDeviceInput(userID int, fingerprint string, now int64) CreateUserDeviceInput {
	runtimeFamily := "node"
	evidencePresent := true
	return CreateUserDeviceInput{
		UserId:                userID,
		FingerprintHash:       deviceTestHash(fingerprint),
		CompatibilityHash:     deviceTestHash("compat-" + fingerprint),
		Status:                string(constant.UserDevicePending),
		ClientFamily:          "Codex Desktop",
		ClientVersion:         "0.150",
		OSFamily:              "Windows",
		Architecture:          "amd64",
		Originator:            "codex",
		Confidence:            "high",
		RuntimeFamily:         &runtimeFamily,
		InstallationIDPresent: &evidencePresent,
		WindowIDPresent:       &evidencePresent,
		UserAgentHash:         deviceTestHash("ua-" + fingerprint),
		TLSFingerprintHash:    deviceTestHash("tls-" + fingerprint),
		HTTP2FingerprintHash:  deviceTestHash("h2-" + fingerprint),
		IPHash:                deviceTestHash("ip-" + fingerprint),
		IP:                    "192.0.2.1",
		Now:                   now,
	}
}

func TestUserDeviceDetailReturnsSafeFingerprintEvidence(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-safe-evidence")
	input := observedDeviceInput(user.Id, "safe-evidence", time.Now().Unix())
	device, fingerprint, err := CreateObservedUserDevice(input)
	require.NoError(t, err)

	detail, err := GetUserDeviceDetail(user.Id, device.Id)
	require.NoError(t, err)
	require.Len(t, detail.Fingerprints, 1)
	visible := detail.Fingerprints[0]
	require.NotNil(t, visible.RuntimeFamily)
	assert.Equal(t, "node", *visible.RuntimeFamily)
	require.NotNil(t, visible.InstallationIDPresent)
	assert.True(t, *visible.InstallationIDPresent)
	require.NotNil(t, visible.WindowIDPresent)
	assert.True(t, *visible.WindowIDPresent)
	assert.True(t, visible.UserAgentPresent)
	assert.True(t, visible.JA4Present)
	assert.True(t, visible.HTTP2Present)

	payload, err := common.Marshal(detail)
	require.NoError(t, err)
	serialized := string(payload)
	assert.NotContains(t, serialized, fingerprint.FingerprintHash)
	assert.NotContains(t, serialized, fingerprint.CompatibilityHash)
	assert.NotContains(t, serialized, fingerprint.UserAgentHash)
	assert.NotContains(t, serialized, fingerprint.TLSFingerprintHash)
	assert.NotContains(t, serialized, fingerprint.HTTP2FingerprintHash)
}

func TestUserDeviceCreateObservedReusesUniqueFingerprint(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-unique-fingerprint")
	input := observedDeviceInput(user.Id, "fingerprint", time.Now().Unix())

	const attempts = 4
	type result struct {
		device      *UserDevice
		fingerprint *UserDeviceFingerprint
		err         error
	}
	results := make(chan result, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			device, fingerprint, err := CreateObservedUserDevice(input)
			results <- result{device: device, fingerprint: fingerprint, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var deviceID, fingerprintID int
	for item := range results {
		require.NoError(t, item.err)
		require.NotNil(t, item.device)
		require.NotNil(t, item.fingerprint)
		if deviceID == 0 {
			deviceID = item.device.Id
			fingerprintID = item.fingerprint.Id
		}
		assert.Equal(t, deviceID, item.device.Id)
		assert.Equal(t, fingerprintID, item.fingerprint.Id)
	}

	var deviceCount, fingerprintCount int64
	require.NoError(t, DB.Model(&UserDevice{}).Where("user_id = ?", user.Id).Count(&deviceCount).Error)
	require.NoError(t, DB.Model(&UserDeviceFingerprint{}).Where("user_id = ?", user.Id).Count(&fingerprintCount).Error)
	assert.EqualValues(t, 1, deviceCount)
	assert.EqualValues(t, 1, fingerprintCount)
}

func TestUserDevicePaginationStableAndUpdatesStayWithOwner(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-pagination-owner")
	other := createDeviceTestUser(t, "device-pagination-other")
	now := time.Now().Unix()
	var devices []*UserDevice
	for _, name := range []string{"one", "two", "three"} {
		device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, name, now))
		require.NoError(t, err)
		devices = append(devices, device)
	}

	page := &common.PageInfo{Page: 1, PageSize: 2}
	listed, total, err := ListUserDevices(user.Id, "", page)
	require.NoError(t, err)
	require.Len(t, listed, 2)
	assert.EqualValues(t, 3, total)
	assert.Equal(t, devices[2].Id, listed[0].Id)
	assert.Equal(t, devices[1].Id, listed[1].Id)

	status := string(constant.UserDeviceAllowed)
	err = UpdateUserDevice(other.Id, devices[0].Id, UserDevicePatch{Status: &status})
	assert.Error(t, err)

	var unchanged UserDevice
	require.NoError(t, DB.First(&unchanged, devices[0].Id).Error)
	assert.Equal(t, string(constant.UserDevicePending), unchanged.Status)
}

func TestUserDeviceAllowedTrustsOnlyNonBlockedFingerprints(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-allow-owner")
	device, initial, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "initial", time.Now().Unix()))
	require.NoError(t, err)

	grace := string(constant.DeviceFingerprintGrace)
	blocked := string(constant.DeviceFingerprintBlocked)
	_, err = AttachUserDeviceFingerprint(AttachFingerprintInput{
		UserId: user.Id, DeviceId: device.Id,
		FingerprintHash: deviceTestHash("grace"), CompatibilityHash: deviceTestHash("compat-grace"),
		Status: grace, ClientVersion: "0.151", FirstSeenAt: 100, LastSeenAt: 100,
	})
	require.NoError(t, err)
	_, err = AttachUserDeviceFingerprint(AttachFingerprintInput{
		UserId: user.Id, DeviceId: device.Id,
		FingerprintHash: deviceTestHash("blocked"), CompatibilityHash: deviceTestHash("compat-blocked"),
		Status: blocked, ClientVersion: "0.149", FirstSeenAt: 100, LastSeenAt: 100,
	})
	require.NoError(t, err)

	allowed := string(constant.UserDeviceAllowed)
	require.NoError(t, UpdateUserDevice(user.Id, device.Id, UserDevicePatch{Status: &allowed}))

	detail, err := GetUserDeviceDetail(user.Id, device.Id)
	require.NoError(t, err)
	statuses := make(map[int]string, len(detail.Fingerprints))
	for _, fingerprint := range detail.Fingerprints {
		statuses[fingerprint.Id] = fingerprint.Status
	}
	assert.Equal(t, string(constant.DeviceFingerprintTrusted), statuses[initial.Id])
	for _, fingerprint := range detail.Fingerprints {
		if fingerprint.Id != initial.Id {
			if fingerprint.Status == blocked {
				assert.Equal(t, blocked, statuses[fingerprint.Id])
			} else {
				assert.Equal(t, string(constant.DeviceFingerprintTrusted), statuses[fingerprint.Id])
			}
		}
	}

	var stored User
	require.NoError(t, DB.First(&stored, user.Id).Error)
	assert.EqualValues(t, 2, stored.AccessPolicyVersion)
	trustedCount, err := CountAllowedTrustedDevices(user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, 1, trustedCount)

	require.NoError(t, UpdateUserDevice(user.Id, device.Id, UserDevicePatch{Status: &allowed}))
	require.NoError(t, DB.First(&stored, user.Id).Error)
	assert.EqualValues(t, 2, stored.AccessPolicyVersion)
}

func TestUserDeviceAdministratorStatusUpdatesAreStrictAndUserScoped(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-status-owner")
	other := createDeviceTestUser(t, "device-status-other")
	device, fingerprint, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "status", time.Now().Unix()))
	require.NoError(t, err)

	emptyStatus := ""
	err = UpdateUserDevice(user.Id, device.Id, UserDevicePatch{Status: &emptyStatus})
	assert.ErrorIs(t, err, ErrInvalidUserDeviceStatus)

	err = UpdateUserDeviceFingerprint(other.Id, device.Id, fingerprint.Id, string(constant.DeviceFingerprintTrusted))
	assert.Error(t, err)

	require.NoError(t, UpdateUserDeviceFingerprint(
		user.Id,
		device.Id,
		fingerprint.Id,
		string(constant.DeviceFingerprintTrusted),
	))
	var storedUser User
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.EqualValues(t, 2, storedUser.AccessPolicyVersion)
	var storedFingerprint UserDeviceFingerprint
	require.NoError(t, DB.First(&storedFingerprint, fingerprint.Id).Error)
	assert.Equal(t, string(constant.DeviceFingerprintTrusted), storedFingerprint.Status)
}

func TestHardDeleteUserRemovesDeviceDataInDependencyOrder(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-hard-delete")
	device, fingerprint, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "delete", time.Now().Unix()))
	require.NoError(t, err)
	require.NoError(t, DB.Create(&UserDeviceIP{
		UserId: user.Id, DeviceId: device.Id, IPHash: deviceTestHash("extra-ip"), IP: "192.0.2.2",
		FirstSeenAt: 1, LastSeenAt: 1, RequestCount: 1,
	}).Error)

	require.NoError(t, HardDeleteUserById(user.Id))
	for _, record := range []any{&UserDeviceFingerprint{}, &UserDeviceIP{}, &UserDevice{}} {
		var count int64
		require.NoError(t, DB.Unscoped().Model(record).Where("user_id = ?", user.Id).Count(&count).Error)
		assert.Zero(t, count)
	}
	assert.NotZero(t, fingerprint.Id)
}

func TestDeleteStalePendingUserDevicesCleansAliasesAndIPs(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-stale-cleanup")
	now := time.Now().Unix()
	old := now - 91*24*60*60
	stale, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "stale", old))
	require.NoError(t, err)
	fresh, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "fresh", now))
	require.NoError(t, err)
	allowed, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "allowed", old))
	require.NoError(t, err)
	blocked, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "blocked", old))
	require.NoError(t, err)

	allowedStatus := string(constant.UserDeviceAllowed)
	blockedStatus := string(constant.UserDeviceBlocked)
	require.NoError(t, UpdateUserDevice(user.Id, allowed.Id, UserDevicePatch{Status: &allowedStatus}))
	require.NoError(t, UpdateUserDevice(user.Id, blocked.Id, UserDevicePatch{Status: &blockedStatus}))
	require.NoError(t, DeleteStalePendingUserDevices(now-90*24*60*60))

	var count int64
	require.NoError(t, DB.Model(&UserDevice{}).Where("id = ?", stale.Id).Count(&count).Error)
	assert.Zero(t, count)
	require.NoError(t, DB.Model(&UserDeviceFingerprint{}).Where("device_id = ?", stale.Id).Count(&count).Error)
	assert.Zero(t, count)
	require.NoError(t, DB.Model(&UserDeviceIP{}).Where("device_id = ?", stale.Id).Count(&count).Error)
	assert.Zero(t, count)
	require.NoError(t, DB.Model(&UserDevice{}).Where("id IN ?", []int{fresh.Id, allowed.Id, blocked.Id}).Count(&count).Error)
	assert.EqualValues(t, 3, count)
}

func TestUserDeviceIPHistoryIsCappedAt256Rows(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-ip-cap")
	now := time.Now().Unix()
	var device *UserDevice
	for i := 0; i < 257; i++ {
		input := observedDeviceInput(user.Id, "ip-cap", now+int64(i))
		input.IPHash = deviceTestHash(fmt.Sprintf("ip-%03d", i))
		input.IP = fmt.Sprintf("2001:db8::%x", i+1)
		var err error
		device, _, err = CreateObservedUserDevice(input)
		require.NoError(t, err)
	}

	var count int64
	require.NoError(t, DB.Model(&UserDeviceIP{}).Where("user_id = ? AND device_id = ?", user.Id, device.Id).Count(&count).Error)
	assert.EqualValues(t, 256, count)
	var oldestCount int64
	require.NoError(t, DB.Model(&UserDeviceIP{}).Where("device_id = ? AND ip = ?", device.Id, "2001:db8::1").Count(&oldestCount).Error)
	assert.Zero(t, oldestCount)
	var newest UserDeviceIP
	require.NoError(t, DB.Where("user_id = ? AND device_id = ? AND ip = ?", user.Id, device.Id, "2001:db8::101").First(&newest).Error)
	assert.Equal(t, "2001:db8::101", newest.IP)
	detail, err := GetUserDeviceDetail(user.Id, device.Id)
	require.NoError(t, err)
	require.Len(t, detail.RecentIPs, 10)
	assert.Equal(t, "2001:db8::101", detail.RecentIPs[0].IP)
	assert.Equal(t, "2001:db8::100", detail.RecentIPs[1].IP)
}

func TestUserDeviceAndFingerprintLimits(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-limits")
	now := time.Now().Unix()
	var firstDevice *UserDevice
	for i := 0; i < maxUserDevices; i++ {
		device, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, fmt.Sprintf("device-%03d", i), now+int64(i)))
		require.NoError(t, err)
		if firstDevice == nil {
			firstDevice = device
		}
	}
	_, _, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "device-over-limit", now+maxUserDevices))
	assert.ErrorIs(t, err, ErrUserDeviceLimit)

	for i := 1; i < maxUserDeviceFingerprints; i++ {
		_, err = AttachUserDeviceFingerprint(AttachFingerprintInput{
			UserId:            user.Id,
			DeviceId:          firstDevice.Id,
			FingerprintHash:   deviceTestHash(fmt.Sprintf("alias-%03d", i)),
			CompatibilityHash: deviceTestHash(fmt.Sprintf("alias-compat-%03d", i)),
			Status:            string(constant.DeviceFingerprintPending),
			LastSeenAt:        now + int64(i),
		})
		require.NoError(t, err)
	}
	_, err = AttachUserDeviceFingerprint(AttachFingerprintInput{
		UserId:            user.Id,
		DeviceId:          firstDevice.Id,
		FingerprintHash:   deviceTestHash("alias-over-limit"),
		CompatibilityHash: deviceTestHash("alias-compat-over-limit"),
		Status:            string(constant.DeviceFingerprintPending),
		LastSeenAt:        now + maxUserDeviceFingerprints,
	})
	assert.ErrorIs(t, err, ErrUserDeviceFingerprintLimit)
}

func TestApplyUserDeviceStatsBatchUpdatesWithoutVersionBump(t *testing.T) {
	truncateTables(t)
	user := createDeviceTestUser(t, "device-stats-batch")
	device, fingerprint, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "stats", 100))
	require.NoError(t, err)

	require.NoError(t, ApplyUserDeviceStats([]UserDeviceStatsUpdate{
		{
			UserId: user.Id, DeviceId: device.Id, FingerprintId: fingerprint.Id,
			RequestCount: 3, DeniedCount: 1, LastSeenAt: 200,
			IPHash: deviceTestHash("stats-ip"), IP: "192.0.2.9", ClientVersion: "0.151",
		},
	}))

	var storedDevice UserDevice
	require.NoError(t, DB.First(&storedDevice, device.Id).Error)
	assert.EqualValues(t, 4, storedDevice.RequestCount)
	assert.EqualValues(t, 1, storedDevice.DeniedCount)
	assert.EqualValues(t, 200, storedDevice.LastSeenAt)
	assert.Equal(t, "0.151", storedDevice.LastClientVersion)
	var storedFingerprint UserDeviceFingerprint
	require.NoError(t, DB.First(&storedFingerprint, fingerprint.Id).Error)
	assert.EqualValues(t, 4, storedFingerprint.RequestCount)
	assert.EqualValues(t, 200, storedFingerprint.LastSeenAt)
	assert.Equal(t, "0.151", storedFingerprint.ClientVersion)
	var storedUser User
	require.NoError(t, DB.First(&storedUser, user.Id).Error)
	assert.EqualValues(t, 1, storedUser.AccessPolicyVersion)
}

func TestUserDeviceConfiguredDatabases(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		dbType  common.DatabaseType
		open    func(string) (*gorm.DB, error)
	}{
		{
			name:    "mysql",
			envName: "TEST_MYSQL_DSN",
			dbType:  common.DatabaseTypeMySQL,
			open: func(dsn string) (*gorm.DB, error) {
				return gorm.Open(mysql.Open(dsn), &gorm.Config{})
			},
		},
		{
			name:    "postgres",
			envName: "TEST_POSTGRES_DSN",
			dbType:  common.DatabaseTypePostgreSQL,
			open: func(dsn string) (*gorm.DB, error) {
				return gorm.Open(postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true}), &gorm.Config{})
			},
		},
	}
	configured := false
	for _, test := range tests {
		dsn := strings.TrimSpace(os.Getenv(test.envName))
		if dsn == "" {
			continue
		}
		configured = true
		t.Run(test.name, func(t *testing.T) {
			db, err := test.open(dsn)
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			t.Cleanup(func() { _ = sqlDB.Close() })

			oldDB, oldLogDB := DB, LOG_DB
			oldMainType, oldLogType := common.MainDatabaseType(), common.LogDatabaseType()
			DB, LOG_DB = db, db
			common.SetDatabaseTypes(test.dbType, test.dbType)
			initCol()
			t.Cleanup(func() {
				DB, LOG_DB = oldDB, oldLogDB
				common.SetDatabaseTypes(oldMainType, oldLogType)
				initCol()
			})

			require.NoError(t, db.AutoMigrate(&User{}, &UserDevice{}, &UserDeviceFingerprint{}, &UserDeviceIP{}))
			assert.True(t, db.Migrator().HasColumn(&User{}, "device_controls_enabled"))
			assert.True(t, db.Migrator().HasColumn(&UserDevice{}, "rate_limit_rpm"))
			assert.True(t, db.Migrator().HasColumn(&UserDevice{}, "blocked_models"))
			username := fmt.Sprintf("cross-%d", time.Now().UnixNano()%1000000000)
			user := createDeviceTestUser(t, username)
			device, fingerprint, err := CreateObservedUserDevice(observedDeviceInput(user.Id, "cross-db", time.Now().Unix()))
			require.NoError(t, err)
			require.NotNil(t, device)
			require.NotNil(t, fingerprint)
			listed, total, err := ListUserDevices(user.Id, "", &common.PageInfo{Page: 1, PageSize: 10})
			require.NoError(t, err)
			assert.EqualValues(t, 1, total)
			require.Len(t, listed, 1)
			_, err = GetUserDeviceDetail(user.Id, device.Id)
			require.NoError(t, err)

			allowed := string(constant.UserDeviceAllowed)
			require.NoError(t, UpdateUserDevice(user.Id, device.Id, UserDevicePatch{Status: &allowed}))
			count, err := CountAllowedTrustedDevices(user.Id)
			require.NoError(t, err)
			assert.EqualValues(t, 1, count)

			require.NoError(t, db.Model(&User{}).Where("id = ?", user.Id).
				Update("device_policy_mode", string(constant.UserDevicePolicyObserve)).Error)
			rpm := 60
			blockedModels := []string{" gpt-5.6-terra ", "gpt-5.6-sol", "gpt-5.6-sol"}
			mutation, err := UpdateUserDeviceWithSnapshot(user.Id, device.Id, UserDevicePatch{
				RateLimitRPM:  &rpm,
				BlockedModels: &blockedModels,
			})
			require.NoError(t, err)
			assert.True(t, mutation.ControlsChanged)
			require.NoError(t, InitializeUserDeviceControls())
			require.NoError(t, InitializeUserDeviceControls())
			var controlledDevice UserDevice
			require.NoError(t, db.First(&controlledDevice, device.Id).Error)
			assert.Equal(t, 60, controlledDevice.RateLimitRPM)
			assert.JSONEq(t, `["gpt-5.6-sol","gpt-5.6-terra"]`, controlledDevice.BlockedModelsJSON)
			var controlledUser User
			require.NoError(t, db.First(&controlledUser, user.Id).Error)
			assert.True(t, controlledUser.DeviceControlsEnabled)

			const attempts = 4
			raceInput := observedDeviceInput(user.Id, "cross-db-race", time.Now().Unix())
			type raceResult struct {
				device      *UserDevice
				fingerprint *UserDeviceFingerprint
				err         error
			}
			results := make(chan raceResult, attempts)
			var wg sync.WaitGroup
			for range attempts {
				wg.Add(1)
				go func() {
					defer wg.Done()
					device, fingerprint, err := CreateObservedUserDevice(raceInput)
					results <- raceResult{device: device, fingerprint: fingerprint, err: err}
				}()
			}
			wg.Wait()
			close(results)
			var raceDeviceID, raceFingerprintID int
			for result := range results {
				require.NoError(t, result.err)
				require.NotNil(t, result.device)
				require.NotNil(t, result.fingerprint)
				if raceDeviceID == 0 {
					raceDeviceID = result.device.Id
					raceFingerprintID = result.fingerprint.Id
				}
				assert.Equal(t, raceDeviceID, result.device.Id)
				assert.Equal(t, raceFingerprintID, result.fingerprint.Id)
			}

			sharedAlias := deviceTestHash("cross-db-shared-alias")
			attachResults := make(chan error, 2)
			for _, deviceID := range []int{device.Id, raceDeviceID} {
				wg.Add(1)
				go func(targetDeviceID int) {
					defer wg.Done()
					_, err := AttachUserDeviceFingerprint(AttachFingerprintInput{
						UserId:            user.Id,
						DeviceId:          targetDeviceID,
						FingerprintHash:   sharedAlias,
						CompatibilityHash: deviceTestHash("cross-db-shared-compat"),
						Status:            string(constant.DeviceFingerprintPending),
						LastSeenAt:        time.Now().Unix(),
					})
					attachResults <- err
				}(deviceID)
			}
			wg.Wait()
			close(attachResults)
			var attached, conflicted int
			for err := range attachResults {
				switch {
				case err == nil:
					attached++
				case errors.Is(err, ErrUserDeviceFingerprintConflict):
					conflicted++
				default:
					require.NoError(t, err)
				}
			}
			assert.Equal(t, 1, attached)
			assert.Equal(t, 1, conflicted)

			for _, record := range []any{&UserDeviceFingerprint{}, &UserDeviceIP{}, &UserDevice{}} {
				require.NoError(t, db.Unscoped().Where("user_id = ?", user.Id).Delete(record).Error)
			}
			require.NoError(t, db.Unscoped().Delete(&User{}, user.Id).Error)
		})
	}
	if !configured {
		t.Skip("set TEST_MYSQL_DSN or TEST_POSTGRES_DSN to run configured database checks")
	}
}
