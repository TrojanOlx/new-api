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
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type userDeviceControlsAPIDetail struct {
	Device struct {
		RateLimitRPM  int      `json:"rate_limit_rpm"`
		BlockedModels []string `json:"blocked_models"`
	} `json:"device"`
	Fingerprints []json.RawMessage `json:"fingerprints"`
	RecentIPs    []json.RawMessage `json:"recent_ips"`
}

type userDeviceControlsAPIEnvelope struct {
	Success bool                        `json:"success"`
	Code    string                      `json:"code"`
	Data    userDeviceControlsAPIDetail `json:"data"`
}

type userDeviceControlsAPIListEnvelope struct {
	Success bool `json:"success"`
	Data    struct {
		Items []struct {
			RateLimitRPM      int `json:"rate_limit_rpm"`
			BlockedModelCount int `json:"blocked_model_count"`
		} `json:"items"`
	} `json:"data"`
}

func TestUpdateUserDeviceControlsMergesOmittedFieldsAndReturnsFullDetail(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Updates(map[string]any{
		"device_policy_mode": string(constant.UserDevicePolicyObserve),
	}).Error)

	device := &model.UserDevice{
		UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "controls-api-compatibility-hash",
		ClientFamily:      "Codex Desktop", OSFamily: "Windows", Architecture: "amd64",
		Originator: "codex", Confidence: "high", FirstSeenAt: 10, LastSeenAt: 20,
		FirstIP: "203.0.113.10", LastIP: "203.0.113.10", ObservedIPCount: 1,
		RateLimitRPM: 45, BlockedModelsJSON: `["legacy-model"]`,
	}
	require.NoError(t, fixture.db.Create(device).Error)
	require.NoError(t, fixture.db.Create(&model.UserDeviceFingerprint{
		UserId: fixture.user.Id, DeviceId: device.Id, FingerprintHash: "controls-api-fingerprint-hash",
		CompatibilityHash: device.CompatibilityHash, Status: string(constant.DeviceFingerprintPending),
		FirstSeenAt: 10, LastSeenAt: 20,
	}).Error)
	require.NoError(t, fixture.db.Create(&model.UserDeviceIP{
		UserId: fixture.user.Id, DeviceId: device.Id, IPHash: "controls-api-ip-hash",
		IP: "203.0.113.10", FirstSeenAt: 10, LastSeenAt: 20,
	}).Error)

	response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root,
		map[string]any{"rate_limit_rpm": 240})
	require.Equal(t, http.StatusOK, response.Code)

	var envelope userDeviceControlsAPIEnvelope
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	require.True(t, envelope.Success)
	assert.Equal(t, 240, envelope.Data.Device.RateLimitRPM)
	assert.Equal(t, []string{"legacy-model"}, envelope.Data.Device.BlockedModels)
	assert.NotNil(t, envelope.Data.Fingerprints)
	assert.NotNil(t, envelope.Data.RecentIPs)

	response = userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root,
		map[string]any{"blocked_models": []string{"zeta-model", "alpha-model"}})
	require.Equal(t, http.StatusOK, response.Code)
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	assert.Equal(t, 240, envelope.Data.Device.RateLimitRPM)
	assert.Equal(t, []string{"alpha-model", "zeta-model"}, envelope.Data.Device.BlockedModels)
}

func TestListUserDevicesReturnsControlSummary(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device := &model.UserDevice{
		UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "controls-api-list-compatibility-hash",
		FirstSeenAt:       10, LastSeenAt: 20, RateLimitRPM: 75,
		BlockedModelsJSON: `["gpt-5.6-sol","image-model"]`,
	}
	require.NoError(t, fixture.db.Create(device).Error)

	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet,
		"/api/user/"+strconv.Itoa(fixture.user.Id)+"/devices", fixture.root, nil)
	require.Equal(t, http.StatusOK, response.Code)
	var envelope userDeviceControlsAPIListEnvelope
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	require.True(t, envelope.Success)
	require.Len(t, envelope.Data.Items, 1)
	assert.Equal(t, 75, envelope.Data.Items[0].RateLimitRPM)
	assert.Equal(t, 2, envelope.Data.Items[0].BlockedModelCount)
}

func TestUpdateUserDeviceControlsRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		body map[string]any
	}{
		{name: "negative RPM", body: map[string]any{"rate_limit_rpm": -1}},
		{name: "RPM above maximum", body: map[string]any{"rate_limit_rpm": 60001}},
		{name: "too many blocked models", body: map[string]any{
			"blocked_models": func() []string {
				models := make([]string, 129)
				for i := range models {
					models[i] = fmt.Sprintf("model-%03d", i)
				}
				return models
			}(),
		}},
		{name: "blocked model ID above byte limit", body: map[string]any{
			"blocked_models": []string{strings.Repeat("x", 129)},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := setupUserAccessPolicyControllerTest(t)
			require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Updates(map[string]any{
				"device_policy_mode": string(constant.UserDevicePolicyObserve),
			}).Error)
			device := &model.UserDevice{
				UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
				CompatibilityHash: "controls-api-invalid-compatibility-hash",
				FirstSeenAt:       10, LastSeenAt: 20,
			}
			require.NoError(t, fixture.db.Create(device).Error)

			response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root, test.body)
			assert.Equal(t, http.StatusBadRequest, response.Code)
		})
	}
}

func TestUpdateUserDeviceControlsRejectsNonEmptyControlsWhenPolicyIsOff(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device := &model.UserDevice{
		UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "controls-api-policy-off-compatibility-hash",
		FirstSeenAt:       10, LastSeenAt: 20,
	}
	require.NoError(t, fixture.db.Create(device).Error)

	response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root,
		map[string]any{"blocked_models": []string{"policy-off-model"}})
	assert.Equal(t, http.StatusBadRequest, response.Code)

	var stored model.UserDevice
	require.NoError(t, fixture.db.First(&stored, device.Id).Error)
	assert.Equal(t, 0, stored.RateLimitRPM)
	assert.True(t, strings.TrimSpace(stored.BlockedModelsJSON) == "" || stored.BlockedModelsJSON == "[]")
}

func TestUpdateUserDeviceControlsRejectsDeviceOwnedByAnotherUser(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	device, _ := seedUserAccessPolicyTestDevice(t, fixture.db, fixture.user2.Id,
		string(constant.UserDevicePending), string(constant.DeviceFingerprintPending), 'c')

	response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root,
		map[string]any{"rate_limit_rpm": 120})
	assert.Equal(t, http.StatusNotFound, response.Code)

	var stored model.UserDevice
	require.NoError(t, fixture.db.First(&stored, device.Id).Error)
	assert.Equal(t, 0, stored.RateLimitRPM)
}

func TestUpdateUserDeviceControlsUsesTargetRoleGuard(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	targets := []struct {
		name   string
		actor  *model.User
		target *model.User
	}{
		{name: "same-rank administrator", actor: fixture.admin, target: fixture.admin2},
		{name: "root target", actor: fixture.admin, target: fixture.root},
	}
	for _, test := range targets {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", test.target.Id).Updates(map[string]any{
				"device_policy_mode": string(constant.UserDevicePolicyObserve),
			}).Error)
			device := &model.UserDevice{
				UserId: test.target.Id, Status: string(constant.UserDevicePending),
				CompatibilityHash: "controls-api-role-compatibility-hash-" + strconv.Itoa(test.target.Id),
				FirstSeenAt:       10, LastSeenAt: 20,
			}
			require.NoError(t, fixture.db.Create(device).Error)

			response := userDeviceControlsAPIRequest(t, http.MethodPatch, test.target.Id, device.Id, test.actor,
				map[string]any{"rate_limit_rpm": 120})
			assert.Equal(t, http.StatusForbidden, response.Code)
		})
	}

	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.admin2.Id).Updates(map[string]any{
		"device_policy_mode": string(constant.UserDevicePolicyObserve),
	}).Error)
	rootManagedDevice := &model.UserDevice{
		UserId: fixture.admin2.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "controls-api-root-compatibility-hash", FirstSeenAt: 10, LastSeenAt: 20,
	}
	require.NoError(t, fixture.db.Create(rootManagedDevice).Error)
	response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.admin2.Id, rootManagedDevice.Id, fixture.root,
		map[string]any{"rate_limit_rpm": 120})
	assert.Equal(t, http.StatusOK, response.Code)
	var envelope userDeviceControlsAPIEnvelope
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	assert.Equal(t, 120, envelope.Data.Device.RateLimitRPM)
}

func TestUserDeviceControlsCacheFailureReturnsUnavailableWithConsistentState(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Updates(map[string]any{
		"device_policy_mode": string(constant.UserDevicePolicyObserve),
	}).Error)
	device := &model.UserDevice{
		UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "controls-api-cache-compatibility-hash", FirstSeenAt: 10, LastSeenAt: 20,
	}
	require.NoError(t, fixture.db.Create(device).Error)
	var before model.User
	require.NoError(t, fixture.db.First(&before, fixture.user.Id).Error)

	previous := updateUserDeviceForAdmin
	updateUserDeviceForAdmin = func(userID, deviceID int, patch model.UserDevicePatch) (*model.UserDeviceMutation, error) {
		mutation, err := previous(userID, deviceID, patch)
		if err != nil {
			return mutation, err
		}
		return mutation, fmt.Errorf("%w: injected", model.ErrUserAccessPolicyCachePublish)
	}
	t.Cleanup(func() { updateUserDeviceForAdmin = previous })

	response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root,
		map[string]any{"rate_limit_rpm": 300, "blocked_models": []string{"cache-sensitive-model"}})
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)
	assert.Equal(t, "3", response.Header().Get("Retry-After"))
	var envelope userDeviceControlsAPIEnvelope
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &envelope))
	assert.False(t, envelope.Success)
	assert.Equal(t, "access_control_unavailable", envelope.Code)

	var storedDevice model.UserDevice
	require.NoError(t, fixture.db.First(&storedDevice, device.Id).Error)
	assert.Equal(t, 300, storedDevice.RateLimitRPM)
	assert.Equal(t, `["cache-sensitive-model"]`, storedDevice.BlockedModelsJSON)
	var storedUser model.User
	require.NoError(t, fixture.db.First(&storedUser, fixture.user.Id).Error)
	assert.True(t, storedUser.DeviceControlsEnabled)
	assert.Equal(t, before.AccessPolicyVersion+1, storedUser.AccessPolicyVersion)
}

func TestUserDeviceControlsAuditRedactsSensitiveValues(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Updates(map[string]any{
		"device_policy_mode": string(constant.UserDevicePolicyObserve),
	}).Error)
	fingerprintHash := "audit-controls-fingerprint-hash"
	deviceIP := "198.51.100.74"
	device := &model.UserDevice{
		UserId: fixture.user.Id, Status: string(constant.UserDevicePending),
		CompatibilityHash: "audit-controls-compatibility-hash", FirstIP: deviceIP, LastIP: deviceIP,
		FirstSeenAt: 10, LastSeenAt: 20, RateLimitRPM: 30, BlockedModelsJSON: `["old-private-model"]`,
	}
	require.NoError(t, fixture.db.Create(device).Error)
	require.NoError(t, fixture.db.Create(&model.UserDeviceFingerprint{
		UserId: fixture.user.Id, DeviceId: device.Id, FingerprintHash: fingerprintHash,
		CompatibilityHash: device.CompatibilityHash, Status: string(constant.DeviceFingerprintPending),
		FirstSeenAt: 10, LastSeenAt: 20,
	}).Error)
	require.NoError(t, fixture.db.Create(&model.UserDeviceIP{
		UserId: fixture.user.Id, DeviceId: device.Id, IPHash: "audit-controls-ip-hash",
		IP: deviceIP, FirstSeenAt: 10, LastSeenAt: 20,
	}).Error)

	response := userDeviceControlsAPIRequest(t, http.MethodPatch, fixture.user.Id, device.Id, fixture.root,
		map[string]any{"rate_limit_rpm": 90, "blocked_models": []string{"new-private-model", "second-private-model"}, "remark": "secret operator remark"})
	require.Equal(t, http.StatusOK, response.Code)

	var audit model.Log
	require.NoError(t, fixture.db.Where("type = ?", model.LogTypeManage).Order("id DESC").First(&audit).Error)
	for _, forbidden := range []string{deviceIP, fingerprintHash, device.CompatibilityHash, "old-private-model", "new-private-model", "second-private-model", "secret operator remark"} {
		assert.NotContains(t, audit.Other, forbidden)
	}
	var auditEnvelope struct {
		Operation struct {
			Params map[string]any `json:"params"`
		} `json:"op"`
	}
	require.NoError(t, common.UnmarshalJsonStr(audit.Other, &auditEnvelope))
	assert.Equal(t, float64(fixture.user.Id), auditEnvelope.Operation.Params["target_user_id"])
	assert.Equal(t, float64(device.Id), auditEnvelope.Operation.Params["device_id"])
	assert.Equal(t, float64(30), auditEnvelope.Operation.Params["old_rate_limit_rpm"])
	assert.Equal(t, float64(90), auditEnvelope.Operation.Params["rate_limit_rpm"])
	assert.Equal(t, float64(1), auditEnvelope.Operation.Params["old_blocked_model_count"])
	assert.Equal(t, float64(2), auditEnvelope.Operation.Params["blocked_model_count"])
	assert.Equal(t, true, auditEnvelope.Operation.Params["controls_changed"])
	assert.Equal(t, true, auditEnvelope.Operation.Params["remark_changed"])
}

func TestGetUserModelsByAdminReturnsTargetModelsAndUsesTargetRoleGuard(t *testing.T) {
	fixture := setupUserAccessPolicyControllerTest(t)
	require.NoError(t, fixture.db.AutoMigrate(&model.Ability{}))
	targetGroup := "controls-api-target-group"
	require.NoError(t, fixture.db.Model(&model.User{}).Where("id = ?", fixture.user.Id).Update("group", targetGroup).Error)
	require.NoError(t, fixture.db.Create(&[]model.Ability{
		{Group: targetGroup, Model: "controls-target-usable-model", ChannelId: 1, Enabled: true},
		{Group: targetGroup, Model: "controls-target-disabled-model", ChannelId: 2, Enabled: false},
	}).Error)

	path := "/api/user/" + strconv.Itoa(fixture.user.Id) + "/models?group=" + targetGroup
	response := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet, path, fixture.admin, nil)
	require.Equal(t, http.StatusOK, response.Code)
	var modelsResponse struct {
		Success bool     `json:"success"`
		Data    []string `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &modelsResponse))
	require.True(t, modelsResponse.Success)
	assert.Equal(t, []string{"controls-target-usable-model"}, modelsResponse.Data)

	sameRank := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet,
		"/api/user/"+strconv.Itoa(fixture.admin2.Id)+"/models?group="+targetGroup, fixture.admin, nil)
	assert.Equal(t, http.StatusForbidden, sameRank.Code)
	rootTarget := userAccessPolicyTestRequest(t, fixture.router, http.MethodGet,
		"/api/user/"+strconv.Itoa(fixture.root.Id)+"/models?group="+targetGroup, fixture.admin, nil)
	assert.Equal(t, http.StatusForbidden, rootTarget.Code)
}

func userDeviceControlsAPIPath(userID, deviceID int) string {
	return "/api/user/" + strconv.Itoa(userID) + "/devices/" + strconv.Itoa(deviceID)
}

func userDeviceControlsAPIRequest(t *testing.T, method string, targetUserID, deviceID int, actor *model.User, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = common.Marshal(body)
		require.NoError(t, err)
	}
	request := httptest.NewRequest(method, userDeviceControlsAPIPath(targetUserID, deviceID), bytes.NewReader(payload))
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = request
	context.Params = gin.Params{
		{Key: "id", Value: strconv.Itoa(targetUserID)},
		{Key: "device_id", Value: strconv.Itoa(deviceID)},
	}
	context.Set("id", actor.Id)
	context.Set("role", actor.Role)
	context.Set("username", actor.Username)
	context.Set("use_access_token", true)
	UpdateUserDevice(context)
	return response
}
