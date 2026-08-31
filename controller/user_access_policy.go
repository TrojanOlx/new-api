package controller

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var (
	updateUserAccessPolicyForAdmin      = model.UpdateUserAccessPolicyForAdminWithSnapshot
	updateUserDeviceForAdmin            = model.UpdateUserDeviceWithSnapshot
	updateUserDeviceFingerprintForAdmin = model.UpdateUserDeviceFingerprintWithSnapshot
)

func writeUserAccessControllerError(c *gin.Context, status int, err error) {
	c.JSON(status, gin.H{"success": false, "message": err.Error()})
}

func writeUserAccessUnavailable(c *gin.Context) {
	c.Header("Retry-After", "3")
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"success": false,
		"code":    string(types.ErrorCodeAccessControlUnavailable),
		"message": common.TranslateMessage(c, i18n.MsgUserAccessUnavailable),
	})
}

func managedAccessTarget(c *gin.Context) (*model.User, bool) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil || userID <= 0 {
		writeUserAccessControllerError(c, http.StatusBadRequest, errors.New("invalid user id"))
		return nil, false
	}
	user, err := model.GetUserById(userID, false)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeUserAccessControllerError(c, http.StatusNotFound, errors.New("user not found"))
		} else {
			writeUserAccessControllerError(c, http.StatusInternalServerError, err)
		}
		return nil, false
	}
	if !canManageTargetRole(c.GetInt("role"), user.Role) {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": common.TranslateMessage(c, i18n.MsgUserNoPermissionSameLevel),
		})
		return nil, false
	}
	return user, true
}

func parsePositiveResourceID(c *gin.Context, name string) (int, bool) {
	value, err := strconv.Atoi(c.Param(name))
	if err != nil || value <= 0 {
		writeUserAccessControllerError(c, http.StatusBadRequest, errors.New("invalid "+name))
		return 0, false
	}
	return value, true
}

func buildUserAccessPolicyResponse(user *model.User) (dto.UserAccessPolicyResponse, error) {
	ipMode := user.APIIPMode
	if ipMode == "" {
		ipMode = string(constant.UserIPPolicyUnrestricted)
	}
	deviceMode := user.DevicePolicyMode
	if deviceMode == "" {
		deviceMode = string(constant.UserDevicePolicyOff)
	}
	allowlist := make([]string, 0)
	if user.APIIPAllowlist != "" {
		if err := common.Unmarshal([]byte(user.APIIPAllowlist), &allowlist); err != nil {
			return dto.UserAccessPolicyResponse{}, err
		}
	}
	if allowlist == nil {
		allowlist = make([]string, 0)
	}
	version := user.AccessPolicyVersion
	if version < 1 {
		version = 1
	}
	return dto.UserAccessPolicyResponse{
		UserId: user.Id, IPMode: ipMode, IPAllowlist: allowlist, DeviceMode: deviceMode,
		AccessPolicyVersion: version, FingerprintReady: common.DeviceFingerprintReady(),
		UpgradeGraceHours:          common.DeviceUpgradeGraceHours,
		ActiveNetworkWindowMinutes: common.DeviceActiveNetworkWindowMinutes,
	}, nil
}

func GetUserAccessPolicy(c *gin.Context) {
	user, ok := managedAccessTarget(c)
	if !ok {
		return
	}
	response, err := buildUserAccessPolicyResponse(user)
	if err != nil {
		writeUserAccessControllerError(c, http.StatusInternalServerError, err)
		return
	}
	common.ApiSuccess(c, response)
}

func UpdateUserAccessPolicy(c *gin.Context) {
	current, ok := managedAccessTarget(c)
	if !ok {
		return
	}
	var request dto.UserAccessPolicyUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		writeUserAccessControllerError(c, http.StatusBadRequest, err)
		return
	}
	if request.IPMode != nil {
		normalized := strings.TrimSpace(*request.IPMode)
		if !constant.IsValidUserIPPolicyMode(normalized) {
			writeUserAccessControllerError(c, http.StatusBadRequest, errors.New("invalid user IP policy mode"))
			return
		}
		request.IPMode = &normalized
	}
	if request.DeviceMode != nil {
		normalized := strings.TrimSpace(*request.DeviceMode)
		if !constant.IsValidUserDevicePolicyMode(normalized) {
			writeUserAccessControllerError(c, http.StatusBadRequest, errors.New("invalid user device policy mode"))
			return
		}
		request.DeviceMode = &normalized
	}

	patch := model.UserAccessPolicyPatch{IPMode: request.IPMode, DeviceMode: request.DeviceMode}
	if request.IPAllowlist != nil {
		normalized, err := common.NormalizeIPAllowlist(*request.IPAllowlist)
		if err != nil {
			writeUserAccessControllerError(c, http.StatusBadRequest, err)
			return
		}
		encoded, err := common.Marshal(normalized)
		if err != nil {
			writeUserAccessControllerError(c, http.StatusInternalServerError, err)
			return
		}
		allowlistJSON := string(encoded)
		patch.IPAllowlistJSON = &allowlistJSON
	}
	mutation, err := updateUserAccessPolicyForAdmin(current.Id, patch)
	if mutation != nil && mutation.Changed {
		oldResponse, oldErr := buildUserAccessPolicyResponse(&mutation.Before)
		response, responseErr := buildUserAccessPolicyResponse(&mutation.After)
		if oldErr == nil && responseErr == nil {
			recordManageAuditFor(c, current.Id, "user.access_policy_update", map[string]interface{}{
				"target_user_id": current.Id,
				"old_ip_mode":    oldResponse.IPMode, "new_ip_mode": response.IPMode,
				"old_device_mode": oldResponse.DeviceMode, "new_device_mode": response.DeviceMode,
				"old_allowlist_count": len(oldResponse.IPAllowlist), "allowlist_count": len(response.IPAllowlist),
			})
		}
	}
	if err != nil {
		if errors.Is(err, model.ErrUserAccessPolicyCachePublish) ||
			errors.Is(err, model.ErrUserDeviceAllowlistSecretUnavailable) {
			writeUserAccessUnavailable(c)
			return
		}
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			status = http.StatusNotFound
		case errors.Is(err, common.ErrUserIPAllowlistEmpty),
			errors.Is(err, model.ErrUserDeviceAllowlistTrustedDeviceRequired),
			errors.Is(err, model.ErrUserDeviceControlsMustBeCleared):
			status = http.StatusBadRequest
		}
		writeUserAccessControllerError(c, status, err)
		return
	}
	response, err := buildUserAccessPolicyResponse(&mutation.After)
	if err != nil {
		writeUserAccessControllerError(c, http.StatusInternalServerError, err)
		return
	}
	common.ApiSuccess(c, response)
}

func ListUserDevices(c *gin.Context) {
	user, ok := managedAccessTarget(c)
	if !ok {
		return
	}
	page := common.GetPageQuery(c)
	devices, total, err := model.ListUserDevices(user.Id, c.Query("status"), page)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, model.ErrInvalidUserDeviceStatus) {
			status = http.StatusBadRequest
		}
		writeUserAccessControllerError(c, status, err)
		return
	}
	page.SetTotal(int(total))
	page.SetItems(devices)
	common.ApiSuccess(c, page)
}

func GetUserDevice(c *gin.Context) {
	user, ok := managedAccessTarget(c)
	if !ok {
		return
	}
	deviceID, ok := parsePositiveResourceID(c, "device_id")
	if !ok {
		return
	}
	detail, err := model.GetUserDeviceDetail(user.Id, deviceID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeUserAccessControllerError(c, http.StatusNotFound, errors.New("device not found"))
		} else {
			writeUserAccessControllerError(c, http.StatusInternalServerError, err)
		}
		return
	}
	common.ApiSuccess(c, detail)
}

func UpdateUserDevice(c *gin.Context) {
	user, ok := managedAccessTarget(c)
	if !ok {
		return
	}
	deviceID, ok := parsePositiveResourceID(c, "device_id")
	if !ok {
		return
	}
	var request dto.UserDeviceUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		writeUserAccessControllerError(c, http.StatusBadRequest, err)
		return
	}
	if request.Status != nil {
		normalized := strings.TrimSpace(*request.Status)
		if !constant.IsValidUserDeviceStatus(normalized) {
			writeUserAccessControllerError(c, http.StatusBadRequest, model.ErrInvalidUserDeviceStatus)
			return
		}
		request.Status = &normalized
	}
	if request.Remark != nil && utf8.RuneCountInString(*request.Remark) > 255 {
		writeUserAccessControllerError(c, http.StatusBadRequest, errors.New("device remark is too long"))
		return
	}
	mutation, err := updateUserDeviceForAdmin(user.Id, deviceID, model.UserDevicePatch{
		Status: request.Status, Remark: request.Remark,
		RateLimitRPM: request.RateLimitRPM, BlockedModels: request.BlockedModels,
	})
	if mutation != nil && mutation.Changed {
		params := map[string]interface{}{
			"target_user_id": user.Id,
			"device_id":      deviceID, "old_status": mutation.Before.Status, "status": mutation.After.Status,
			"remark_changed":     mutation.RemarkChanged,
			"old_rate_limit_rpm": mutation.Before.RateLimitRPM, "rate_limit_rpm": mutation.After.RateLimitRPM,
			"rate_limit_changed":     mutation.Before.RateLimitRPM != mutation.After.RateLimitRPM,
			"blocked_models_changed": mutation.Before.BlockedModelsJSON != mutation.After.BlockedModelsJSON,
			"controls_changed":       mutation.ControlsChanged,
		}
		beforeControls, beforeErr := mutation.Before.RequestControls()
		afterControls, afterErr := mutation.After.RequestControls()
		if beforeErr == nil && afterErr == nil {
			params["old_blocked_model_count"] = len(beforeControls.BlockedModels)
			params["blocked_model_count"] = len(afterControls.BlockedModels)
		}
		recordManageAuditFor(c, user.Id, "user.device_status_update", params)
	}
	if err != nil {
		if errors.Is(err, model.ErrUserAccessPolicyCachePublish) {
			writeUserAccessUnavailable(c)
			return
		}
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			status = http.StatusNotFound
		case errors.Is(err, model.ErrInvalidUserDeviceRateLimit),
			errors.Is(err, model.ErrInvalidUserDeviceBlockedModels),
			errors.Is(err, model.ErrUserDeviceControlsRequirePolicy):
			status = http.StatusBadRequest
		}
		writeUserAccessControllerError(c, status, err)
		return
	}
	after, err := model.GetUserDeviceDetail(user.Id, deviceID)
	if err != nil {
		writeUserAccessControllerError(c, http.StatusInternalServerError, err)
		return
	}
	common.ApiSuccess(c, after)
}

func UpdateUserDeviceFingerprint(c *gin.Context) {
	user, ok := managedAccessTarget(c)
	if !ok {
		return
	}
	deviceID, ok := parsePositiveResourceID(c, "device_id")
	if !ok {
		return
	}
	fingerprintID, ok := parsePositiveResourceID(c, "fingerprint_id")
	if !ok {
		return
	}
	var request dto.UserDeviceFingerprintUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil || request.Status == nil {
		if err == nil {
			err = errors.New("fingerprint status is required")
		}
		writeUserAccessControllerError(c, http.StatusBadRequest, err)
		return
	}
	status := strings.TrimSpace(*request.Status)
	if status == string(constant.DeviceFingerprintGrace) || !constant.IsValidUserDeviceFingerprintStatus(status) {
		writeUserAccessControllerError(c, http.StatusBadRequest, model.ErrInvalidUserDeviceFingerprintStatus)
		return
	}
	mutation, err := updateUserDeviceFingerprintForAdmin(user.Id, deviceID, fingerprintID, status)
	if mutation != nil && mutation.Changed {
		recordManageAuditFor(c, user.Id, "user.device_fingerprint_status_update", map[string]interface{}{
			"target_user_id": user.Id,
			"device_id":      deviceID, "fingerprint_id": fingerprintID, "short_id": mutation.Before.ShortId,
			"old_status": mutation.Before.Status, "status": mutation.After.Status,
		})
	}
	if err != nil {
		if errors.Is(err, model.ErrUserAccessPolicyCachePublish) {
			writeUserAccessUnavailable(c)
			return
		}
		responseStatus := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			responseStatus = http.StatusNotFound
		}
		writeUserAccessControllerError(c, responseStatus, err)
		return
	}
	after, err := model.GetUserDeviceDetail(user.Id, deviceID)
	if err != nil {
		writeUserAccessControllerError(c, http.StatusInternalServerError, err)
		return
	}
	common.ApiSuccess(c, after)
}
