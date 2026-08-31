package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type userAccessPolicyTestEnvelope struct {
	Success bool            `json:"success"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type userAccessPolicyTestFixture struct {
	db     *gorm.DB
	router *gin.Engine
	root   *model.User
	admin  *model.User
	admin2 *model.User
	user   *model.User
	user2  *model.User
}

func setupUserAccessPolicyControllerTest(t *testing.T) userAccessPolicyTestFixture {
	t.Helper()
	previousDB, previousLogDB := model.DB, model.LOG_DB
	previousRedis := common.RedisEnabled
	previousMainType, previousLogType := common.MainDatabaseType(), common.LogDatabaseType()
	previousSecret := common.DeviceFingerprintSecret

	gin.SetMode(gin.TestMode)
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.UserSession{}, &model.UserDevice{},
		&model.UserDeviceFingerprint{}, &model.UserDeviceIP{}, &model.Log{},
	))
	model.DB, model.LOG_DB = db, db
	common.SetDatabaseTypes(common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	common.DeviceFingerprintSecret = "controller-device-secret-0123456789abcdef"

	createUser := func(username string, role int) *model.User {
		pat := "pat-" + username
		user := &model.User{
			Username: username, Password: "unused-password", DisplayName: username,
			Role: role, Status: common.UserStatusEnabled, Group: "default",
			AffCode: "aff-" + username, AccessToken: &pat, AuthVersion: 1,
			APIIPMode: string(constant.UserIPPolicyUnrestricted), APIIPAllowlist: "[]",
			DevicePolicyMode: string(constant.UserDevicePolicyOff), AccessPolicyVersion: 1,
		}
		require.NoError(t, db.Create(user).Error)
		return user
	}
	fixture := userAccessPolicyTestFixture{
		db:     db,
		root:   createUser("access-root", common.RoleRootUser),
		admin:  createUser("access-admin", common.RoleAdminUser),
		admin2: createUser("access-admin-2", common.RoleAdminUser),
		user:   createUser("access-user", common.RoleCommonUser),
		user2:  createUser("access-user-2", common.RoleCommonUser),
	}
	router := gin.New()
	adminRoute := router.Group("/api/user")
	adminRoute.Use(middleware.AdminAuth())
	adminRoute.GET("/:id/access-policy", GetUserAccessPolicy)
	adminRoute.PATCH("/:id/access-policy", UpdateUserAccessPolicy)
	adminRoute.GET("/:id/models", GetUserModels)
	adminRoute.GET("/:id/devices", ListUserDevices)
	adminRoute.GET("/:id/devices/:device_id", GetUserDevice)
	adminRoute.PATCH("/:id/devices/:device_id", UpdateUserDevice)
	adminRoute.PATCH("/:id/devices/:device_id/fingerprints/:fingerprint_id", UpdateUserDeviceFingerprint)
	fixture.router = router

	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
		common.RedisEnabled = previousRedis
		common.SetDatabaseTypes(previousMainType, previousLogType)
		common.DeviceFingerprintSecret = previousSecret
		sqlDB, dbErr := db.DB()
		if dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return fixture
}

func userAccessPolicyTestRequest(t *testing.T, router http.Handler, method, path string, user *model.User, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload := []byte(nil)
	if body != nil {
		var err error
		payload, err = common.Marshal(body)
		require.NoError(t, err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.RemoteAddr = "192.0.2.10:12345"
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if user != nil {
		require.NotNil(t, user.AccessToken)
		request.Header.Set("Authorization", "Bearer "+*user.AccessToken)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func decodeUserAccessPolicyTestEnvelope(t *testing.T, response *httptest.ResponseRecorder) userAccessPolicyTestEnvelope {
	t.Helper()
	var envelope userAccessPolicyTestEnvelope
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	return envelope
}

func seedUserAccessPolicyTestDevice(t *testing.T, db *gorm.DB, userID int, status, fingerprintStatus string, suffix byte) (*model.UserDevice, *model.UserDeviceFingerprint) {
	t.Helper()
	runtimeFamily := "node"
	evidencePresent := true
	device := &model.UserDevice{
		UserId: userID, Status: status, CompatibilityHash: strings.Repeat(string(suffix), 64),
		ClientFamily: "Codex Desktop", OSFamily: "Windows", Architecture: "amd64",
		Originator: "codex", Confidence: "high", FirstSeenAt: 10, LastSeenAt: 20,
		FirstIP: "203.0.113.10", LastIP: "203.0.113.10", ObservedIPCount: 1,
	}
	require.NoError(t, db.Create(device).Error)
	fingerprint := &model.UserDeviceFingerprint{
		UserId: userID, DeviceId: device.Id, FingerprintHash: strings.Repeat(string(suffix+1), 64),
		CompatibilityHash: device.CompatibilityHash, Status: fingerprintStatus,
		RuntimeFamily: &runtimeFamily, InstallationIDPresent: &evidencePresent, WindowIDPresent: &evidencePresent,
		UserAgentHash: strings.Repeat(string(suffix+2), 64), TLSFingerprintHash: strings.Repeat(string(suffix+3), 64),
		HTTP2FingerprintHash: strings.Repeat(string(suffix+4), 64), FirstSeenAt: 10, LastSeenAt: 20,
	}
	require.NoError(t, db.Create(fingerprint).Error)
	require.NoError(t, db.Create(&model.UserDeviceIP{
		UserId: userID, DeviceId: device.Id, IPHash: strings.Repeat(string(suffix+5), 64),
		IP: "203.0.113.10", FirstSeenAt: 10, LastSeenAt: 20,
	}).Error)
	return device, fingerprint
}

func TestUserAccessPolicyRoutesEnforceAuthenticationAndTargetRole(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, fingerprint := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDevicePending), string(constant.DeviceFingerprintPending), 'r')
	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"

	devicePath := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices/" + strconv.Itoa(device.Id)
	routes := []struct {
		method string
		path   string
		body   any
	}{
		{method: http.MethodGet, path: path},
		{method: http.MethodPatch, path: path, body: map[string]any{}},
		{method: http.MethodGet, path: "/api/user/" + strconv.Itoa(fixture.user.Id) + "/models"},
		{method: http.MethodGet, path: "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices"},
		{method: http.MethodGet, path: devicePath},
		{method: http.MethodPatch, path: devicePath, body: map[string]any{}},
		{method: http.MethodPatch, path: devicePath + "/fingerprints/" + strconv.Itoa(fingerprint.Id), body: map[string]any{"status": "trusted"}},
	}
	for _, route := range routes {
		unauthenticated := userAccessPolicyTestRequest(t, fixture.router, route.method, route.path, nil, route.body)
		assert.Equal(t, http.StatusUnauthorized, unauthenticated.Code, "%s %s", route.method, route.path)

		ordinary := userAccessPolicyTestRequest(t, fixture.router, route.method, route.path, fixture.user, route.body)
		assert.Equal(t, http.StatusForbidden, ordinary.Code, "%s %s", route.method, route.path)
	}

	peerPath := "/api/user/" + strconv.Itoa(fixture.admin2.Id) + "/access-policy"
	peer := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, peerPath, fixture.admin, nil)
	assert.Equal(t, http.StatusForbidden, peer.Code)

	rootPath := "/api/user/" + strconv.Itoa(fixture.root.Id) + "/access-policy"
	rootByAdmin := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, rootPath, fixture.admin, nil)
	assert.Equal(t, http.StatusForbidden, rootByAdmin.Code)

	rootSelf := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, rootPath, fixture.root, nil)
	assert.Equal(t, http.StatusOK, rootSelf.Code)
	assert.True(t, decodeUserAccessPolicyTestEnvelope(t, rootSelf).Success)
}

func TestUpdateUserAccessPolicyPreservesOmittedFields(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Updates(map[string]any{
		"api_ip_mode": string(constant.UserIPPolicyAllowlist), "api_ip_allowlist": `["203.0.113.0/24"]`,
		"device_policy_mode": string(constant.UserDevicePolicyObserve),
	}).Error)

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"device_mode": string(constant.UserDevicePolicyBlacklist),
	})
	require.Equal(t, http.StatusOK, response.Code)
	envelope := decodeUserAccessPolicyTestEnvelope(t, response)
	require.True(t, envelope.Success, envelope.Message)
	var policy struct {
		IPMode      string   `json:"ip_mode"`
		IPAllowlist []string `json:"ip_allowlist"`
		DeviceMode  string   `json:"device_mode"`
	}
	require.NoError(t, common.Unmarshal(envelope.Data, &policy))
	assert.Equal(t, string(constant.UserIPPolicyAllowlist), policy.IPMode)
	assert.Equal(t, []string{"203.0.113.0/24"}, policy.IPAllowlist)
	assert.Equal(t, string(constant.UserDevicePolicyBlacklist), policy.DeviceMode)
}

func TestUpdateUserAccessPolicyRequiresTrustedDeviceForDeviceAllowlist(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"device_mode": string(constant.UserDevicePolicyAllowlist),
	})
	assert.Equal(t, http.StatusBadRequest, response.Code)

	seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDeviceAllowed), string(constant.DeviceFingerprintTrusted), 'a')
	response = userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"device_mode": string(constant.UserDevicePolicyAllowlist),
	})
	require.Equal(t, http.StatusOK, response.Code)
	assert.True(t, decodeUserAccessPolicyTestEnvelope(t, response).Success)
}

func TestUpdateUserAccessPolicyRejectsDeviceAllowlistWhenFingerprintSecretIsUnavailable(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDeviceAllowed), string(constant.DeviceFingerprintTrusted), 's')
	common.DeviceFingerprintSecret = ""

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"device_mode": string(constant.UserDevicePolicyAllowlist),
	})
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Equal(t, "3", response.Header().Get("Retry-After"))
	assert.Equal(t, "access_control_unavailable", decodeUserAccessPolicyTestEnvelope(t, response).Code)
}

func TestUpdateUserAccessPolicyRejectsTurningDeviceModeOffWithActiveControls(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Updates(map[string]any{
		"device_policy_mode":      string(constant.UserDevicePolicyObserve),
		"device_controls_enabled": true,
	}).Error)
	require.NoError(t, fixture.db.Create(&model.UserDevice{
		UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "controls-before-off", RateLimitRPM: 30, BlockedModelsJSON: "[]",
	}).Error)

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"device_mode": string(constant.UserDevicePolicyOff),
	})

	assert.Equal(t, http.StatusBadRequest, response.Code)
}

func TestUserAccessPolicyCommittedCacheFailureReturnsUnavailableAndAudits(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	previous := updateUserAccessPolicyForAdmin
	updateUserAccessPolicyForAdmin = func(userID int, patch model.UserAccessPolicyPatch) (*model.UserAccessPolicyMutation, error) {
		mutation, err := previous(userID, patch)
		if err != nil {
			return mutation, err
		}
		return mutation, fmt.Errorf("%w: injected", model.ErrUserAccessPolicyCachePublish)
	}
	t.Cleanup(func() { updateUserAccessPolicyForAdmin = previous })

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"ip_mode": "allowlist", "ip_allowlist": []string{"198.51.100.20"},
	})
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Equal(t, "3", response.Header().Get("Retry-After"))
	assert.Equal(t, "access_control_unavailable", decodeUserAccessPolicyTestEnvelope(t, response).Code)

	var stored model.User
	require.NoError(t, fixture.db.First(&stored, fixture.user.Id).Error)
	assert.Equal(t, string(constant.UserIPPolicyAllowlist), stored.APIIPMode)
	var audit model.Log
	require.NoError(t, fixture.db.Where("type = ?", model.LogTypeManage).Order("id DESC").First(&audit).Error)
	assert.Contains(t, audit.Other, `"action":"user.access_policy_update"`)
	assert.NotContains(t, audit.Other, "198.51.100.20")
}

func TestUserDeviceCommittedCacheFailureReturnsUnavailableAndAudits(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, _ := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDevicePending), string(constant.DeviceFingerprintPending), 'd')
	previous := updateUserDeviceForAdmin
	updateUserDeviceForAdmin = func(userID, deviceID int, patch model.UserDevicePatch) (*model.UserDeviceMutation, error) {
		mutation, err := previous(userID, deviceID, patch)
		if err != nil {
			return mutation, err
		}
		return mutation, fmt.Errorf("%w: injected", model.ErrUserAccessPolicyCachePublish)
	}
	t.Cleanup(func() { updateUserDeviceForAdmin = previous })

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices/" + strconv.Itoa(device.Id)
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{"status": "blocked"})
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Equal(t, "3", response.Header().Get("Retry-After"))
	assert.Equal(t, "access_control_unavailable", decodeUserAccessPolicyTestEnvelope(t, response).Code)

	var stored model.UserDevice
	require.NoError(t, fixture.db.First(&stored, device.Id).Error)
	assert.Equal(t, string(constant.UserDeviceBlocked), stored.Status)
	var audit model.Log
	require.NoError(t, fixture.db.Where("type = ?", model.LogTypeManage).Order("id DESC").First(&audit).Error)
	assert.Contains(t, audit.Other, `"action":"user.device_status_update"`)
}

func TestUserDeviceFingerprintCommittedCacheFailureReturnsUnavailableAndAudits(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, fingerprint := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDevicePending), string(constant.DeviceFingerprintPending), 'f')
	previous := updateUserDeviceFingerprintForAdmin
	updateUserDeviceFingerprintForAdmin = func(userID, deviceID, fingerprintID int, status string) (*model.UserDeviceFingerprintMutation, error) {
		mutation, err := previous(userID, deviceID, fingerprintID, status)
		if err != nil {
			return mutation, err
		}
		return mutation, fmt.Errorf("%w: injected", model.ErrUserAccessPolicyCachePublish)
	}
	t.Cleanup(func() { updateUserDeviceFingerprintForAdmin = previous })

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices/" + strconv.Itoa(device.Id) +
		"/fingerprints/" + strconv.Itoa(fingerprint.Id)
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{"status": "blocked"})
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Equal(t, "3", response.Header().Get("Retry-After"))
	assert.Equal(t, "access_control_unavailable", decodeUserAccessPolicyTestEnvelope(t, response).Code)

	var stored model.UserDeviceFingerprint
	require.NoError(t, fixture.db.First(&stored, fingerprint.Id).Error)
	assert.Equal(t, string(constant.DeviceFingerprintBlocked), stored.Status)
	var audit model.Log
	require.NoError(t, fixture.db.Where("type = ?", model.LogTypeManage).Order("id DESC").First(&audit).Error)
	assert.Contains(t, audit.Other, `"action":"user.device_fingerprint_status_update"`)
	assert.NotContains(t, audit.Other, fingerprint.FingerprintHash)
}

func TestUserDeviceEndpointsRejectCrossUserResourceIDs(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, fingerprint := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user2.Id,
		string(constant.UserDevicePending), string(constant.DeviceFingerprintPending), 'k')
	base := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices/" + strconv.Itoa(device.Id)

	detail := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, base, fixture.root, nil)
	assert.Equal(t, http.StatusNotFound, detail.Code)
	devicePatch := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, base, fixture.root, map[string]any{"status": "blocked"})
	assert.Equal(t, http.StatusNotFound, devicePatch.Code)
	fingerprintPatch := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch,
		base+"/fingerprints/"+strconv.Itoa(fingerprint.Id), fixture.root, map[string]any{"status": "trusted"})
	assert.Equal(t, http.StatusNotFound, fingerprintPatch.Code)
}

func TestUserDeviceEndpointsReturnSafeListAndDetailShapes(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, fingerprint := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDevicePending), string(constant.DeviceFingerprintPending), 'u')
	base := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices"

	list := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, base+"?p=1&page_size=20", fixture.root, nil)
	require.Equal(t, http.StatusOK, list.Code)
	assert.NotContains(t, list.Body.String(), device.CompatibilityHash)
	assert.NotContains(t, list.Body.String(), fingerprint.FingerprintHash)

	detail := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, base+"/"+strconv.Itoa(device.Id), fixture.root, nil)
	require.Equal(t, http.StatusOK, detail.Code)
	assert.Contains(t, detail.Body.String(), `"fingerprints"`)
	assert.Contains(t, detail.Body.String(), `"recent_ips"`)
	assert.Contains(t, detail.Body.String(), `"runtime_family":"node"`)
	assert.Contains(t, detail.Body.String(), `"installation_id_present":true`)
	assert.Contains(t, detail.Body.String(), `"window_id_present":true`)
	assert.Contains(t, detail.Body.String(), `"user_agent_present":true`)
	assert.Contains(t, detail.Body.String(), `"ja4_present":true`)
	assert.Contains(t, detail.Body.String(), `"http2_present":true`)
	assert.NotContains(t, detail.Body.String(), fingerprint.FingerprintHash)
	assert.NotContains(t, detail.Body.String(), fingerprint.CompatibilityHash)
	assert.NotContains(t, detail.Body.String(), fingerprint.UserAgentHash)
	assert.NotContains(t, detail.Body.String(), fingerprint.TLSFingerprintHash)
	assert.NotContains(t, detail.Body.String(), fingerprint.HTTP2FingerprintHash)

	devicePatch := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, base+"/"+strconv.Itoa(device.Id), fixture.root,
		map[string]any{"status": "allowed", "remark": "Office workstation"})
	require.Equal(t, http.StatusOK, devicePatch.Code)
	assert.Contains(t, devicePatch.Body.String(), `"Office workstation"`)

	fingerprintPatch := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch,
		base+"/"+strconv.Itoa(device.Id)+"/fingerprints/"+strconv.Itoa(fingerprint.Id), fixture.root,
		map[string]any{"status": "blocked"})
	require.Equal(t, http.StatusOK, fingerprintPatch.Code)
	assert.Contains(t, fingerprintPatch.Body.String(), `"status":"blocked"`)
}

func TestUpdateUserDeviceRemarkDoesNotApprovePendingFingerprint(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, fingerprint := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDeviceAllowed), string(constant.DeviceFingerprintPending), 'z')
	var before model.User
	require.NoError(t, fixture.db.First(&before, fixture.user.Id).Error)
	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices/" + strconv.Itoa(device.Id)

	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root,
		map[string]any{"remark": "Renamed only"})
	require.Equal(t, http.StatusOK, response.Code)

	var storedFingerprint model.UserDeviceFingerprint
	require.NoError(t, fixture.db.First(&storedFingerprint, fingerprint.Id).Error)
	assert.Equal(t, string(constant.DeviceFingerprintPending), storedFingerprint.Status)
	var after model.User
	require.NoError(t, fixture.db.First(&after, fixture.user.Id).Error)
	assert.Equal(t, before.AccessPolicyVersion, after.AccessPolicyVersion)
}

func TestUserAccessPolicyAuditOmitsFullIPAndFingerprintHashes(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, fingerprint := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user.Id,
		string(constant.UserDeviceAllowed), string(constant.DeviceFingerprintTrusted), 'A')
	policyPath := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/access-policy"
	policyResponse := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, policyPath, fixture.root, map[string]any{
		"ip_mode": "allowlist", "ip_allowlist": []string{"198.51.100.27"}, "device_mode": "observe",
	})
	require.Equal(t, http.StatusOK, policyResponse.Code)

	fingerprintPath := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/devices/" + strconv.Itoa(device.Id) +
		"/fingerprints/" + strconv.Itoa(fingerprint.Id)
	fingerprintResponse := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, fingerprintPath, fixture.root,
		map[string]any{"status": "blocked"})
	require.Equal(t, http.StatusOK, fingerprintResponse.Code)

	var logs []model.Log
	require.NoError(t, fixture.db.Where("type = ?", model.LogTypeManage).Order("id ASC").Find(&logs).Error)
	require.GreaterOrEqual(t, len(logs), 2)
	for _, log := range logs {
		assert.NotContains(t, log.Other, "198.51.100.27")
		assert.NotContains(t, log.Other, fingerprint.FingerprintHash)
		assert.NotContains(t, log.Other, fingerprint.UserAgentHash)
	}
	assert.Contains(t, logs[0].Other, `"allowlist_count":1`)
	assert.Contains(t, logs[len(logs)-1].Other, `"short_id"`)
}

func TestUserAccessPolicyAuditIncludesTargetForRootSelfUpdate(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	path := "/api/user/" + strconv.Itoa(fixture.root.Id) + "/access-policy"
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodPatch, path, fixture.root, map[string]any{
		"ip_mode": "allowlist", "ip_allowlist": []string{"203.0.113.50"},
	})
	require.Equal(t, http.StatusOK, response.Code)

	var log model.Log
	require.NoError(t, fixture.db.Where("type = ?", model.LogTypeManage).Order("id DESC").First(&log).Error)
	var other struct {
		Operation struct {
			Params map[string]any `json:"params"`
		} `json:"op"`
	}
	require.NoError(t, common.UnmarshalJsonStr(log.Other, &other))
	assert.Equal(t, float64(fixture.root.Id), other.Operation.Params["target_user_id"])
}

func TestBuildSelfUserDataExcludesAdministratorAccessControlFields(t *testing.T) {
	data := buildSelfUserData(&model.User{
		Id: 1, Username: "self-user", Role: common.RoleCommonUser,
		APIIPMode: "allowlist", APIIPAllowlist: `["203.0.113.10"]`,
		DevicePolicyMode: "allowlist", DeviceControlsEnabled: true, AccessPolicyVersion: 9,
	})
	for _, field := range []string{"api_ip_mode", "api_ip_allowlist", "device_policy_mode", "device_controls_enabled", "access_policy_version"} {
		_, present := data[field]
		assert.False(t, present, "self DTO exposed %s", field)
	}
}
