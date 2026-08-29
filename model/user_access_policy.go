package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"

	"gorm.io/gorm"
)

var ErrUserAccessPolicyCachePending = errors.New("user access policy update is pending")
var ErrUserAccessPolicyVersionConflict = errors.New("user access policy version update conflicted")

type UserAccessPolicyPatch struct {
	IPMode          *string
	IPAllowlistJSON *string
	DeviceMode      *string
}

func getUserAccessPolicyFenceKey(userId int) string {
	return fmt.Sprintf("access:user:fence:%d", userId)
}

func getUserAccessPolicyVersionKey(userId int) string {
	return fmt.Sprintf("access:user:version:%d", userId)
}

func getUserAccessPolicyVersionFloor(userId int) (int64, error) {
	if !common.RedisEnabled {
		return 0, nil
	}
	values, err := common.RDB.MGet(context.Background(), getUserAccessPolicyFenceKey(userId), getUserAccessPolicyVersionKey(userId)).Result()
	if err != nil {
		return 0, err
	}
	var floor int64
	for _, value := range values {
		if value == nil {
			continue
		}
		parsed, err := strconv.ParseInt(fmt.Sprint(value), 10, 64)
		if err != nil {
			return 0, err
		}
		if parsed > floor {
			floor = parsed
		}
	}
	return floor, nil
}

func SetUserAccessPolicyVersionFence(userId int, version int64) error {
	if !common.RedisEnabled {
		return nil
	}
	if userId <= 0 || version <= 0 {
		return fmt.Errorf("invalid user access policy fence")
	}
	const script = `
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local incoming = tonumber(ARGV[1])
if current < incoming then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
elseif current == incoming then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
elseif redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 1`
	return common.RDB.Eval(context.Background(), script, []string{getUserAccessPolicyFenceKey(userId)}, version, userAuthFenceTTLSeconds()).Err()
}

func publishCommittedUserAccessPolicyVersion(userId int, version int64) error {
	if !common.RedisEnabled {
		return nil
	}
	if userId <= 0 || version <= 0 {
		return fmt.Errorf("invalid committed user access policy version")
	}
	const script = `
local incoming = tonumber(ARGV[1])
local committed = tonumber(redis.call('GET', KEYS[1]) or '0')
local pending = tonumber(redis.call('GET', KEYS[2]) or '0')
if committed < incoming then
  redis.call('SET', KEYS[1], ARGV[1])
end
if pending > 0 and pending <= incoming then
  redis.call('DEL', KEYS[2])
end
return 1`
	return common.RDB.Eval(context.Background(), script,
		[]string{getUserAccessPolicyVersionKey(userId), getUserAccessPolicyFenceKey(userId)}, version,
	).Err()
}

func IncrementUserAccessPolicyVersionWithTx(tx *gorm.DB, userId int) (int64, error) {
	if tx == nil || userId <= 0 {
		return 0, fmt.Errorf("invalid user access policy version update")
	}
	for range 3 {
		var user User
		if err := lockForUpdate(tx.Unscoped()).Select("id", "access_policy_version").Where("id = ?", userId).First(&user).Error; err != nil {
			return 0, err
		}
		current := user.AccessPolicyVersion
		if current < 1 {
			current = 1
		}
		next := current + 1
		if err := SetUserAccessPolicyVersionFence(userId, next); err != nil {
			return 0, err
		}
		result := tx.Unscoped().Model(&User{}).
			Where("id = ? AND access_policy_version = ?", userId, user.AccessPolicyVersion).
			Update("access_policy_version", next)
		if result.Error != nil {
			return 0, result.Error
		}
		if result.RowsAffected == 1 {
			return next, nil
		}
	}
	return 0, ErrUserAccessPolicyVersionConflict
}

func PublishUserAccessPolicyCache(userId int) error {
	user, err := GetUserById(userId, false)
	if err != nil {
		return err
	}
	return updateUserCache(*user)
}

func InitializeUserAccessPolicyVersions() error {
	return DB.Model(&User{}).Where("access_policy_version IS NULL OR access_policy_version < ?", 1).Update("access_policy_version", 1).Error
}

func UpdateUserAccessPolicy(userId int, patch UserAccessPolicyPatch) (*User, bool, error) {
	if userId <= 0 {
		return nil, false, fmt.Errorf("invalid user id")
	}
	var updated User
	changed := false
	err := DB.Transaction(func(tx *gorm.DB) error {
		var current User
		if err := lockForUpdate(tx).Where("id = ?", userId).First(&current).Error; err != nil {
			return err
		}

		currentIPMode := current.APIIPMode
		if currentIPMode == "" {
			currentIPMode = string(constant.UserIPPolicyUnrestricted)
		}
		currentDeviceMode := current.DevicePolicyMode
		if currentDeviceMode == "" {
			currentDeviceMode = string(constant.UserDevicePolicyOff)
		}
		currentAllowlistJSON := current.APIIPAllowlist
		if currentAllowlistJSON == "" {
			currentAllowlistJSON = "[]"
		}
		ipMode := currentIPMode
		deviceMode := currentDeviceMode
		allowlistJSON := currentAllowlistJSON

		if patch.IPMode != nil {
			candidate := strings.TrimSpace(*patch.IPMode)
			if !constant.IsValidUserIPPolicyMode(candidate) {
				return fmt.Errorf("invalid user IP policy mode: %s", candidate)
			}
			ipMode = candidate
		}
		if patch.DeviceMode != nil {
			candidate := strings.TrimSpace(*patch.DeviceMode)
			if !constant.IsValidUserDevicePolicyMode(candidate) {
				return fmt.Errorf("invalid user device policy mode: %s", candidate)
			}
			deviceMode = candidate
		}
		if patch.IPAllowlistJSON != nil {
			var values []string
			if err := common.Unmarshal([]byte(*patch.IPAllowlistJSON), &values); err != nil {
				return fmt.Errorf("invalid user IP allowlist: %w", err)
			}
			normalized, err := common.NormalizeIPAllowlist(values)
			if err != nil {
				return err
			}
			encoded, err := common.Marshal(normalized)
			if err != nil {
				return err
			}
			allowlistJSON = string(encoded)
		}
		if ipMode == string(constant.UserIPPolicyAllowlist) {
			var values []string
			if err := common.Unmarshal([]byte(allowlistJSON), &values); err != nil {
				return fmt.Errorf("invalid stored user IP allowlist: %w", err)
			}
			if len(values) == 0 {
				return common.ErrUserIPAllowlistEmpty
			}
		}

		changed = ipMode != currentIPMode || allowlistJSON != currentAllowlistJSON || deviceMode != currentDeviceMode
		if !changed {
			updated = current
			updated.APIIPMode = ipMode
			updated.APIIPAllowlist = allowlistJSON
			updated.DevicePolicyMode = deviceMode
			if updated.AccessPolicyVersion < 1 {
				updated.AccessPolicyVersion = 1
			}
			return nil
		}

		next, err := IncrementUserAccessPolicyVersionWithTx(tx, userId)
		if err != nil {
			return err
		}
		if err := tx.Model(&User{}).Where("id = ?", userId).Updates(map[string]interface{}{
			"api_ip_mode":        ipMode,
			"api_ip_allowlist":   allowlistJSON,
			"device_policy_mode": deviceMode,
		}).Error; err != nil {
			return err
		}
		if err := tx.First(&updated, userId).Error; err != nil {
			return err
		}
		updated.AccessPolicyVersion = next
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if changed {
		if err := PublishUserAccessPolicyCache(userId); err != nil {
			return &updated, true, err
		}
	}
	return &updated, changed, nil
}
