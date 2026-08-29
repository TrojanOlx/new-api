package service

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type fakeUserAccessBackend struct {
	resolution       userDeviceResolution
	resolveErr       error
	conflict         bool
	recorded         []model.UserDeviceStatsUpdate
	beginCalls       int
	releaseCalls     int
	pendingChanges   int
	rejectOnConflict bool
}

func (backend *fakeUserAccessBackend) resolve(*model.UserBase, DeviceFingerprintEvidence, string, string, time.Time) (userDeviceResolution, error) {
	return backend.resolution, backend.resolveErr
}

func (backend *fakeUserAccessBackend) begin(userId, deviceId int, ipHash string, now time.Time, rejectOnConflict bool) (bool, func()) {
	backend.beginCalls++
	backend.rejectOnConflict = rejectOnConflict
	if backend.conflict && rejectOnConflict {
		return true, nil
	}
	return backend.conflict, func() { backend.releaseCalls++ }
}

func (backend *fakeUserAccessBackend) record(update model.UserDeviceStatsUpdate) {
	backend.recorded = append(backend.recorded, update)
}

func (backend *fakeUserAccessBackend) markFingerprintPending(userId, deviceId, fingerprintId int) error {
	backend.pendingChanges++
	return nil
}

func useFakeUserAccessBackend(t *testing.T, backend userAccessPolicyBackend) {
	t.Helper()
	previousBackend := userAccessBackendForAccess
	previousBuilder := buildDeviceFingerprintForAccess
	userAccessBackendForAccess = backend
	buildDeviceFingerprintForAccess = func(DeviceRequestMetadata) (DeviceFingerprintEvidence, error) {
		return DeviceFingerprintEvidence{
			FingerprintHash:   "fingerprint",
			CompatibilityHash: "compatibility",
			ClientVersion:     "0.151",
		}, nil
	}
	t.Cleanup(func() {
		userAccessBackendForAccess = previousBackend
		buildDeviceFingerprintForAccess = previousBuilder
	})
}

func TestUserAccessOffFastPathSkipsFingerprint(t *testing.T) {
	previousBuilder := buildDeviceFingerprintForAccess
	called := 0
	buildDeviceFingerprintForAccess = func(DeviceRequestMetadata) (DeviceFingerprintEvidence, error) {
		called++
		return DeviceFingerprintEvidence{}, errors.New("must not be called")
	}
	t.Cleanup(func() { buildDeviceFingerprintForAccess = previousBuilder })

	result := EvaluateUserAPIAccess(&model.UserBase{
		Id:                  1,
		APIIPMode:           string(constant.UserIPPolicyUnrestricted),
		APIIPAllowlist:      "[]",
		DevicePolicyMode:    string(constant.UserDevicePolicyOff),
		AccessPolicyVersion: 1,
	}, netip.MustParseAddr("192.0.2.10"), DeviceRequestMetadata{UserAgent: "Codex Desktop/0.150"}, time.Unix(1_700_000_000, 0))

	assert.Equal(t, UserAccessAllow, result.Decision)
	assert.Empty(t, result.Reason)
	assert.Nil(t, result.Release)
	assert.Zero(t, called)
}

func TestUserAccessIPPolicyRunsBeforeDevicePolicy(t *testing.T) {
	testCases := []struct {
		name      string
		allowlist string
		clientIP  string
		want      UserAccessDecision
	}{
		{name: "exact address matches", allowlist: `["192.0.2.10"]`, clientIP: "192.0.2.10", want: UserAccessAllow},
		{name: "CIDR matches", allowlist: `["192.0.2.0/24"]`, clientIP: "192.0.2.99", want: UserAccessAllow},
		{name: "outside allowlist", allowlist: `["192.0.2.0/24"]`, clientIP: "198.51.100.10", want: UserAccessDenyIP},
		{name: "invalid cached policy fails closed", allowlist: `{`, clientIP: "192.0.2.10", want: UserAccessUnavailable},
		{name: "normalized empty cached policy is unavailable", allowlist: `[" "]`, clientIP: "192.0.2.10", want: UserAccessUnavailable},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := EvaluateUserAPIAccess(&model.UserBase{
				Id:                  2,
				APIIPMode:           string(constant.UserIPPolicyAllowlist),
				APIIPAllowlist:      testCase.allowlist,
				DevicePolicyMode:    string(constant.UserDevicePolicyOff),
				AccessPolicyVersion: 1,
			}, netip.MustParseAddr(testCase.clientIP), DeviceRequestMetadata{}, time.Unix(1_700_000_000, 0))

			assert.Equal(t, testCase.want, result.Decision)
		})
	}
}

func TestUserAccessFingerprintUnavailableDependsOnEnforcementMode(t *testing.T) {
	previousBuilder := buildDeviceFingerprintForAccess
	buildDeviceFingerprintForAccess = func(DeviceRequestMetadata) (DeviceFingerprintEvidence, error) {
		return DeviceFingerprintEvidence{}, ErrDeviceFingerprintUnavailable
	}
	t.Cleanup(func() { buildDeviceFingerprintForAccess = previousBuilder })

	for _, testCase := range []struct {
		name string
		mode constant.UserDevicePolicyMode
		want UserAccessDecision
	}{
		{name: "allowlist fails closed", mode: constant.UserDevicePolicyAllowlist, want: UserAccessUnavailable},
		{name: "observe degrades open", mode: constant.UserDevicePolicyObserve, want: UserAccessAllow},
		{name: "blacklist degrades open", mode: constant.UserDevicePolicyBlacklist, want: UserAccessAllow},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := EvaluateUserAPIAccess(&model.UserBase{
				Id:                  3,
				APIIPMode:           string(constant.UserIPPolicyUnrestricted),
				APIIPAllowlist:      "[]",
				DevicePolicyMode:    string(testCase.mode),
				AccessPolicyVersion: 1,
			}, netip.MustParseAddr("192.0.2.10"), DeviceRequestMetadata{}, time.Unix(1_700_000_000, 0))

			assert.Equal(t, testCase.want, result.Decision)
			if testCase.want == UserAccessUnavailable {
				require.Equal(t, "device_fingerprint_unavailable", result.Reason)
			}
		})
	}
}

func TestUserAccessDeviceModeMatrix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	testCases := []struct {
		name               string
		mode               constant.UserDevicePolicyMode
		deviceStatus       constant.UserDeviceStatus
		fingerprintStatus  constant.UserDeviceFingerprintStatus
		graceUntil         int64
		conflict           bool
		wantDecision       UserAccessDecision
		wantRecord         bool
		wantRelease        bool
		wantPendingChange  bool
		wantRejectConflict bool
	}{
		{name: "observe pending", mode: constant.UserDevicePolicyObserve, deviceStatus: constant.UserDevicePending, fingerprintStatus: constant.DeviceFingerprintPending, wantDecision: UserAccessAllow, wantRecord: true, wantRelease: true},
		{name: "observe blocked", mode: constant.UserDevicePolicyObserve, deviceStatus: constant.UserDeviceBlocked, fingerprintStatus: constant.DeviceFingerprintBlocked, wantDecision: UserAccessAllow, wantRecord: true, wantRelease: true},
		{name: "blacklist pending", mode: constant.UserDevicePolicyBlacklist, deviceStatus: constant.UserDevicePending, fingerprintStatus: constant.DeviceFingerprintPending, wantDecision: UserAccessAllow, wantRecord: true, wantRelease: true},
		{name: "blacklist blocked device", mode: constant.UserDevicePolicyBlacklist, deviceStatus: constant.UserDeviceBlocked, fingerprintStatus: constant.DeviceFingerprintTrusted, wantDecision: UserAccessDenyDevice, wantRecord: true},
		{name: "blacklist blocked alias", mode: constant.UserDevicePolicyBlacklist, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintBlocked, wantDecision: UserAccessDenyDevice, wantRecord: true},
		{name: "allowlist pending", mode: constant.UserDevicePolicyAllowlist, deviceStatus: constant.UserDevicePending, fingerprintStatus: constant.DeviceFingerprintPending, wantDecision: UserAccessDenyDevice, wantRecord: true},
		{name: "allowlist trusted", mode: constant.UserDevicePolicyAllowlist, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintTrusted, wantDecision: UserAccessAllow, wantRecord: true, wantRelease: true, wantRejectConflict: true},
		{name: "allowlist active grace", mode: constant.UserDevicePolicyAllowlist, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintGrace, graceUntil: now.Add(time.Hour).Unix(), wantDecision: UserAccessAllow, wantRecord: true, wantRelease: true, wantRejectConflict: true},
		{name: "allowlist expired grace", mode: constant.UserDevicePolicyAllowlist, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintGrace, graceUntil: now.Unix(), wantDecision: UserAccessDenyDevice, wantRecord: true},
		{name: "allowlist network conflict", mode: constant.UserDevicePolicyAllowlist, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintTrusted, conflict: true, wantDecision: UserAccessDenyNetwork, wantRecord: true, wantRejectConflict: true},
		{name: "allowlist grace conflict becomes pending", mode: constant.UserDevicePolicyAllowlist, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintGrace, graceUntil: now.Add(time.Hour).Unix(), conflict: true, wantDecision: UserAccessDenyNetwork, wantRecord: true, wantPendingChange: true, wantRejectConflict: true},
		{name: "observe network conflict remains allowed", mode: constant.UserDevicePolicyObserve, deviceStatus: constant.UserDeviceAllowed, fingerprintStatus: constant.DeviceFingerprintTrusted, conflict: true, wantDecision: UserAccessAllow, wantRecord: true, wantRelease: true},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			backend := &fakeUserAccessBackend{
				resolution: userDeviceResolution{
					DeviceId:          10 + index,
					FingerprintId:     100 + index,
					DeviceStatus:      string(testCase.deviceStatus),
					FingerprintStatus: string(testCase.fingerprintStatus),
					GraceUntil:        testCase.graceUntil,
				},
				conflict: testCase.conflict,
			}
			useFakeUserAccessBackend(t, backend)
			user := &model.UserBase{
				Id:                  1000 + index,
				APIIPMode:           string(constant.UserIPPolicyUnrestricted),
				APIIPAllowlist:      "[]",
				DevicePolicyMode:    string(testCase.mode),
				AccessPolicyVersion: 1,
			}

			result := EvaluateUserAPIAccess(user, netip.MustParseAddr("192.0.2.10"), DeviceRequestMetadata{}, now)

			assert.Equal(t, testCase.wantDecision, result.Decision)
			assert.Equal(t, testCase.wantRecord, len(backend.recorded) == 1)
			assert.Equal(t, testCase.wantRelease, result.Release != nil)
			assert.Equal(t, testCase.wantPendingChange, backend.pendingChanges == 1)
			assert.Equal(t, testCase.wantRejectConflict, backend.rejectOnConflict)
			if result.Release != nil {
				result.Release()
				assert.Equal(t, 1, backend.releaseCalls)
			}
			if len(backend.recorded) == 1 {
				update := backend.recorded[0]
				assert.Equal(t, user.Id, update.UserId)
				assert.EqualValues(t, 1, update.RequestCount)
				if testCase.wantDecision == UserAccessAllow {
					assert.Equal(t, "192.0.2.10", update.IP)
					assert.NotEmpty(t, update.IPHash)
					assert.Zero(t, update.DeniedCount)
				} else {
					assert.Empty(t, update.IP, "a rejected IP must not enter recent history")
					assert.Empty(t, update.IPHash)
					assert.EqualValues(t, 1, update.DeniedCount)
				}
			}
		})
	}
}

func TestUserAccessUntrackedLimitIsCachedWithoutStatistics(t *testing.T) {
	backend := &fakeUserAccessBackend{resolution: userDeviceResolution{Untracked: true}}
	useFakeUserAccessBackend(t, backend)

	for _, mode := range []constant.UserDevicePolicyMode{constant.UserDevicePolicyObserve, constant.UserDevicePolicyAllowlist} {
		backend.recorded = nil
		result := EvaluateUserAPIAccess(&model.UserBase{
			Id: 20, APIIPMode: string(constant.UserIPPolicyUnrestricted), APIIPAllowlist: "[]",
			DevicePolicyMode: string(mode), AccessPolicyVersion: 1,
		}, netip.MustParseAddr("192.0.2.10"), DeviceRequestMetadata{}, time.Unix(1_700_000_000, 0))
		if mode == constant.UserDevicePolicyAllowlist {
			assert.Equal(t, UserAccessDenyDevice, result.Decision)
		} else {
			assert.Equal(t, UserAccessAllow, result.Decision)
		}
		assert.Empty(t, backend.recorded)
	}
}

func TestUserAccessIPHashIsVersionedHMAC(t *testing.T) {
	backend := &fakeUserAccessBackend{resolution: userDeviceResolution{
		DeviceId: 1, FingerprintId: 2,
		DeviceStatus: string(constant.UserDeviceAllowed), FingerprintStatus: string(constant.DeviceFingerprintTrusted),
	}}
	useFakeUserAccessBackend(t, backend)
	previousSecret := common.DeviceFingerprintSecret
	common.DeviceFingerprintSecret = "device-fingerprint-test-secret-0123456789"
	t.Cleanup(func() { common.DeviceFingerprintSecret = previousSecret })

	result := EvaluateUserAPIAccess(&model.UserBase{
		Id: 21, APIIPMode: string(constant.UserIPPolicyUnrestricted), APIIPAllowlist: "[]",
		DevicePolicyMode: string(constant.UserDevicePolicyAllowlist), AccessPolicyVersion: 1,
	}, netip.MustParseAddr("::ffff:192.0.2.10"), DeviceRequestMetadata{}, time.Unix(1_700_000_000, 0))
	require.Equal(t, UserAccessAllow, result.Decision)
	require.Len(t, backend.recorded, 1)
	assert.Equal(t, "192.0.2.10", backend.recorded[0].IP)
	assert.Equal(t, common.GenerateHMACWithKey([]byte("device-ip-v1:"+common.DeviceFingerprintSecret), "192.0.2.10"), backend.recorded[0].IPHash)
}

func setupUserAccessPolicyTestDB(t *testing.T) *model.User {
	t.Helper()
	previousDB, previousRedis, previousRDB := model.DB, common.RedisEnabled, common.RDB
	previousSecret, previousGrace := common.DeviceFingerprintSecret, common.DeviceUpgradeGraceHours
	previousStatsApply := deviceAccessStatsApply
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserDevice{}, &model.UserDeviceFingerprint{}, &model.UserDeviceIP{}))
	model.DB = db
	common.RedisEnabled = false
	common.RDB = nil
	common.DeviceFingerprintSecret = "device-fingerprint-test-secret-0123456789"
	common.DeviceUpgradeGraceHours = common.DefaultDeviceUpgradeGraceHours
	resetDeviceActivityState()
	resetDeviceAccessStatsState()
	deviceAccessStatsApply = model.ApplyUserDeviceStats
	userDeviceDecisionCacheMu.Lock()
	userDeviceDecisionCache = make(map[string]userDeviceResolutionCacheEntry)
	userDeviceDecisionCacheMu.Unlock()
	t.Cleanup(func() {
		resetDeviceActivityState()
		resetDeviceAccessStatsState()
		userDeviceDecisionCacheMu.Lock()
		userDeviceDecisionCache = make(map[string]userDeviceResolutionCacheEntry)
		userDeviceDecisionCacheMu.Unlock()
		model.DB, common.RedisEnabled, common.RDB = previousDB, previousRedis, previousRDB
		common.DeviceFingerprintSecret, common.DeviceUpgradeGraceHours = previousSecret, previousGrace
		deviceAccessStatsApply = previousStatsApply
		_ = sqlDB.Close()
	})
	user := &model.User{
		Username: "access-policy-user", Password: "unused", Group: "default",
		Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		AuthVersion: 1, AccessPolicyVersion: 1,
		APIIPMode: string(constant.UserIPPolicyUnrestricted), APIIPAllowlist: "[]",
		DevicePolicyMode: string(constant.UserDevicePolicyAllowlist),
	}
	require.NoError(t, db.Create(user).Error)
	return user
}

func TestUserAccessCachedNewDeviceRecordsSubsequentRequests(t *testing.T) {
	user := setupUserAccessPolicyTestDB(t)
	now := time.Unix(1_700_300_000, 0)
	base := accessPolicyBaseForTest(t, user.Id)
	base.DevicePolicyMode = string(constant.UserDevicePolicyObserve)
	meta := DeviceRequestMetadata{
		UserAgent: "Codex Desktop/0.150 (Windows; x64)", CodexInstallation: "installation-new-device",
		StainlessOS: "windows", StainlessArch: "x86_64", StainlessRuntime: "electron",
	}

	first := EvaluateUserAPIAccess(base, netip.MustParseAddr("192.0.2.40"), meta, now)
	require.Equal(t, UserAccessAllow, first.Decision)
	first.Release()
	second := EvaluateUserAPIAccess(base, netip.MustParseAddr("192.0.2.40"), meta, now.Add(time.Second))
	require.Equal(t, UserAccessAllow, second.Decision)
	second.Release()
	require.NoError(t, FlushDeviceAccessStatsAt(now.Add(2*time.Second)))

	var device model.UserDevice
	require.NoError(t, model.DB.Where("user_id = ?", user.Id).First(&device).Error)
	assert.EqualValues(t, 2, device.RequestCount)
}

func createTrustedUserAccessDevice(t *testing.T, user *model.User, meta DeviceRequestMetadata, ip string, seenAt time.Time) (*model.UserDevice, *model.UserDeviceFingerprint) {
	t.Helper()
	evidence, err := BuildDeviceFingerprint(meta)
	require.NoError(t, err)
	ip = netip.MustParseAddr(ip).Unmap().String()
	ipHash := common.GenerateHMACWithKey([]byte("device-ip-v1:"+common.DeviceFingerprintSecret), ip)
	device, fingerprint, err := model.CreateObservedUserDevice(model.CreateUserDeviceInput{
		UserId: user.Id, FingerprintHash: evidence.FingerprintHash, CompatibilityHash: evidence.CompatibilityHash,
		Status: string(constant.UserDevicePending), ClientFamily: evidence.ClientFamily,
		ClientVersion: evidence.ClientVersion, OSFamily: evidence.OSFamily, Architecture: evidence.Architecture,
		Originator: evidence.Originator, Confidence: evidence.Confidence,
		UserAgentHash: evidence.UserAgentHash, TLSFingerprintHash: evidence.TLSFingerprintHash,
		HTTP2FingerprintHash: evidence.HTTP2FingerprintHash,
		IPHash:               ipHash, IP: ip, FirstSeenAt: seenAt.Unix(), Now: seenAt.Unix(), RequestCount: 1,
	})
	require.NoError(t, err)
	allowed := string(constant.UserDeviceAllowed)
	require.NoError(t, model.UpdateUserDevice(user.Id, device.Id, model.UserDevicePatch{Status: &allowed}))
	require.NoError(t, model.DB.First(fingerprint, fingerprint.Id).Error)
	require.Equal(t, string(constant.DeviceFingerprintTrusted), fingerprint.Status)
	return device, fingerprint
}

func accessPolicyBaseForTest(t *testing.T, userId int) *model.UserBase {
	t.Helper()
	stored, err := model.GetUserById(userId, false)
	require.NoError(t, err)
	return stored.ToBaseUser()
}

func TestUserAccessCodexUpgradeCreatesGraceAliasOnTheSameLogicalDevice(t *testing.T) {
	user := setupUserAccessPolicyTestDB(t)
	now := time.Unix(1_700_000_000, 0)
	baseMeta := DeviceRequestMetadata{
		UserAgent: "Codex Desktop/0.150 (Windows; x64)", Originator: "codex",
		CodexInstallation: "installation-1", StainlessOS: "windows", StainlessArch: "x86_64",
		StainlessRuntime: "electron", StainlessVersion: "0.150", EdgeJA4: "ja4-a", EdgeHTTP2: "h2-a",
	}
	device, _ := createTrustedUserAccessDevice(t, user, baseMeta, "192.0.2.10", now.Add(-time.Hour))
	upgraded := baseMeta
	upgraded.UserAgent = "Codex Desktop/0.151 (Windows; x64)"
	upgraded.StainlessVersion = "0.151"
	upgraded.EdgeJA4 = "ja4-b"

	result := EvaluateUserAPIAccess(accessPolicyBaseForTest(t, user.Id), netip.MustParseAddr("192.0.2.10"), upgraded, now)
	require.Equal(t, UserAccessAllow, result.Decision)
	require.NotNil(t, result.Release)
	result.Release()

	evidence, err := BuildDeviceFingerprint(upgraded)
	require.NoError(t, err)
	fingerprint, attachedDevice, err := model.FindUserDeviceFingerprint(user.Id, evidence.FingerprintHash)
	require.NoError(t, err)
	assert.Equal(t, device.Id, attachedDevice.Id)
	assert.Equal(t, string(constant.DeviceFingerprintGrace), fingerprint.Status)
	assert.Equal(t, now.Add(48*time.Hour).Unix(), fingerprint.GraceUntil)
}

func TestUserAccessZeroGraceExpiresImmediately(t *testing.T) {
	user := setupUserAccessPolicyTestDB(t)
	common.DeviceUpgradeGraceHours = 0
	now := time.Unix(1_700_100_000, 0)
	baseMeta := DeviceRequestMetadata{
		UserAgent: "Codex Desktop/0.150 (Windows; x64)", Originator: "codex",
		CodexInstallation: "installation-2", StainlessOS: "windows", StainlessArch: "x86_64",
		StainlessRuntime: "electron", EdgeJA4: "ja4-a", EdgeHTTP2: "h2-a",
	}
	device, _ := createTrustedUserAccessDevice(t, user, baseMeta, "192.0.2.20", now.Add(-time.Hour))
	upgraded := baseMeta
	upgraded.EdgeJA4 = "ja4-b"

	result := EvaluateUserAPIAccess(accessPolicyBaseForTest(t, user.Id), netip.MustParseAddr("192.0.2.20"), upgraded, now)
	assert.Equal(t, UserAccessDenyDevice, result.Decision)
	assert.Nil(t, result.Release)
	evidence, err := BuildDeviceFingerprint(upgraded)
	require.NoError(t, err)
	fingerprint, attachedDevice, err := model.FindUserDeviceFingerprint(user.Id, evidence.FingerprintHash)
	require.NoError(t, err)
	assert.Equal(t, device.Id, attachedDevice.Id)
	assert.Equal(t, now.Unix(), fingerprint.GraceUntil)
}

func TestUserAccessDecisionCacheIsScopedByPolicyVersion(t *testing.T) {
	user := setupUserAccessPolicyTestDB(t)
	now := time.Unix(1_700_200_000, 0)
	meta := DeviceRequestMetadata{
		UserAgent: "Codex Desktop/0.150 (Windows; x64)", CodexInstallation: "installation-cache",
		StainlessOS: "windows", StainlessArch: "x86_64", StainlessRuntime: "electron",
	}
	_, fingerprint := createTrustedUserAccessDevice(t, user, meta, "192.0.2.30", now.Add(-time.Hour))
	base := accessPolicyBaseForTest(t, user.Id)

	first := EvaluateUserAPIAccess(base, netip.MustParseAddr("192.0.2.30"), meta, now)
	require.Equal(t, UserAccessAllow, first.Decision)
	first.Release()
	require.NoError(t, model.DB.Unscoped().Delete(&model.UserDeviceFingerprint{}, fingerprint.Id).Error)

	fromCache := EvaluateUserAPIAccess(base, netip.MustParseAddr("192.0.2.30"), meta, now.Add(time.Second))
	assert.Equal(t, UserAccessAllow, fromCache.Decision)
	require.NotNil(t, fromCache.Release)
	fromCache.Release()

	newVersion := *base
	newVersion.AccessPolicyVersion++
	cacheMiss := EvaluateUserAPIAccess(&newVersion, netip.MustParseAddr("192.0.2.30"), meta, now.Add(2*time.Second))
	assert.Equal(t, UserAccessDenyDevice, cacheMiss.Decision)
}

func TestUserAccessFingerprintLimitCachesUntrackedDecision(t *testing.T) {
	user := setupUserAccessPolicyTestDB(t)
	now := time.Unix(1_700_400_000, 0)
	baseMeta := DeviceRequestMetadata{
		UserAgent: "Codex Desktop/0.150 (Windows; x64)", CodexInstallation: "installation-alias-limit",
		StainlessOS: "windows", StainlessArch: "x86_64", StainlessRuntime: "electron",
		EdgeJA4: "ja4-0", EdgeHTTP2: "h2-a",
	}
	device, _ := createTrustedUserAccessDevice(t, user, baseMeta, "192.0.2.50", now.Add(-time.Hour))
	for index := 1; index < 20; index++ {
		aliasMeta := baseMeta
		aliasMeta.EdgeJA4 = fmt.Sprintf("ja4-%d", index)
		evidence, err := BuildDeviceFingerprint(aliasMeta)
		require.NoError(t, err)
		_, err = model.AttachUserDeviceFingerprint(model.AttachFingerprintInput{
			UserId: user.Id, DeviceId: device.Id,
			FingerprintHash: evidence.FingerprintHash, CompatibilityHash: evidence.CompatibilityHash,
			Status: string(constant.DeviceFingerprintTrusted), ClientVersion: evidence.ClientVersion,
			UserAgentHash: evidence.UserAgentHash, TLSFingerprintHash: evidence.TLSFingerprintHash,
			HTTP2FingerprintHash: evidence.HTTP2FingerprintHash, FirstSeenAt: now.Unix(), LastSeenAt: now.Unix(),
		})
		require.NoError(t, err)
	}
	overLimit := baseMeta
	overLimit.EdgeJA4 = "ja4-over-limit"
	base := accessPolicyBaseForTest(t, user.Id)

	first := EvaluateUserAPIAccess(base, netip.MustParseAddr("192.0.2.50"), overLimit, now)
	assert.Equal(t, UserAccessDenyDevice, first.Decision)
	assert.Equal(t, "device_untracked", first.Reason)
	second := EvaluateUserAPIAccess(base, netip.MustParseAddr("192.0.2.50"), overLimit, now.Add(time.Second))
	assert.Equal(t, UserAccessDenyDevice, second.Decision)
}
