package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxUserDevices             = 100
	maxUserDeviceFingerprints  = 20
	maxUserDeviceIPs           = 256
	recentUserDeviceIPs        = 10
	stalePendingDeviceLifetime = 90 * 24 * time.Hour
)

var (
	ErrUserDeviceLimit                    = errors.New("user device limit reached")
	ErrUserDeviceFingerprintLimit         = errors.New("user device fingerprint limit reached")
	ErrUserDeviceFingerprintConflict      = errors.New("user device fingerprint belongs to another device")
	ErrInvalidUserDeviceStatus            = errors.New("invalid user device status")
	ErrInvalidUserDeviceFingerprintStatus = errors.New("invalid user device fingerprint status")
)

// UserDevice is a durable logical device profile. Hashes are deliberately not
// serialized; administrator DTOs should expose only short aliases.
type UserDevice struct {
	Id                int    `json:"id" gorm:"primaryKey"`
	UserId            int    `json:"user_id" gorm:"index:idx_user_device_user_status,priority:1"`
	Status            string `json:"status" gorm:"type:varchar(16);index:idx_user_device_user_status,priority:2"`
	CompatibilityHash string `json:"-" gorm:"type:char(64);index:idx_user_device_compatibility"`
	ClientFamily      string `json:"client_family" gorm:"type:varchar(64)"`
	OSFamily          string `json:"os_family" gorm:"type:varchar(32)"`
	Architecture      string `json:"architecture" gorm:"type:varchar(32)"`
	Originator        string `json:"originator" gorm:"type:varchar(64)"`
	Confidence        string `json:"confidence" gorm:"type:varchar(16)"`
	FirstSeenAt       int64  `json:"first_seen_at"`
	LastSeenAt        int64  `json:"last_seen_at" gorm:"index"`
	FirstIP           string `json:"first_ip" gorm:"type:varchar(45)"`
	LastIP            string `json:"last_ip" gorm:"type:varchar(45)"`
	ObservedIPCount   int    `json:"observed_ip_count"`
	RequestCount      int64  `json:"request_count" gorm:"type:bigint"`
	DeniedCount       int64  `json:"denied_count" gorm:"type:bigint"`
	LastClientVersion string `json:"last_client_version" gorm:"type:varchar(64)"`
	Remark            string `json:"remark" gorm:"type:varchar(255)"`
	CreatedAt         int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt         int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserDevice) TableName() string {
	return "user_devices"
}

// UserDeviceFingerprint stores one technical fingerprint alias for a logical
// device. The unique user/hash index makes an alias belong to one user only.
type UserDeviceFingerprint struct {
	Id                   int    `json:"id" gorm:"primaryKey"`
	UserId               int    `json:"user_id" gorm:"uniqueIndex:idx_user_fingerprint,priority:1"`
	DeviceId             int    `json:"device_id" gorm:"index"`
	FingerprintHash      string `json:"-" gorm:"type:char(64);uniqueIndex:idx_user_fingerprint,priority:2"`
	CompatibilityHash    string `json:"-" gorm:"type:char(64);index"`
	Status               string `json:"status" gorm:"type:varchar(16);index"`
	GraceUntil           int64  `json:"grace_until"`
	ClientVersion        string `json:"client_version" gorm:"type:varchar(64)"`
	UserAgentHash        string `json:"-" gorm:"type:char(64)"`
	TLSFingerprintHash   string `json:"-" gorm:"type:char(64)"`
	HTTP2FingerprintHash string `json:"-" gorm:"type:char(64)"`
	ShortId              string `json:"short_id" gorm:"-:all"`
	FirstSeenAt          int64  `json:"first_seen_at"`
	LastSeenAt           int64  `json:"last_seen_at"`
	RequestCount         int64  `json:"request_count" gorm:"type:bigint"`
	CreatedAt            int64  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt            int64  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (UserDeviceFingerprint) TableName() string {
	return "user_device_fingerprints"
}

// UserDeviceIP records a recent IP for a device. IPHash is the lookup key;
// IP is retained for the administrator detail view only.
type UserDeviceIP struct {
	Id           int    `json:"id" gorm:"primaryKey"`
	UserId       int    `json:"user_id" gorm:"index"`
	DeviceId     int    `json:"device_id" gorm:"uniqueIndex:idx_device_ip,priority:1"`
	IPHash       string `json:"-" gorm:"type:char(64);uniqueIndex:idx_device_ip,priority:2"`
	IP           string `json:"ip" gorm:"type:varchar(45)"`
	FirstSeenAt  int64  `json:"first_seen_at"`
	LastSeenAt   int64  `json:"last_seen_at" gorm:"index"`
	RequestCount int64  `json:"request_count" gorm:"type:bigint"`
}

func (UserDeviceIP) TableName() string {
	return "user_device_ips"
}

// CreateUserDeviceInput is the internal, already privacy-filtered input from
// the fingerprint service. It contains hashes, never raw request headers.
type CreateUserDeviceInput struct {
	UserId               int
	FingerprintHash      string
	CompatibilityHash    string
	Status               string
	ClientFamily         string
	ClientVersion        string
	OSFamily             string
	Architecture         string
	Originator           string
	Confidence           string
	UserAgentHash        string
	TLSFingerprintHash   string
	HTTP2FingerprintHash string
	IPHash               string
	IP                   string
	FirstSeenAt          int64
	Now                  int64
	RequestCount         int64
	DeniedCount          int64
}

// AttachFingerprintInput is used when a new technical alias is associated
// with an existing logical device during an upgrade or first observation.
type AttachFingerprintInput struct {
	UserId               int
	DeviceId             int
	FingerprintHash      string
	CompatibilityHash    string
	Status               string
	GraceUntil           int64
	ClientVersion        string
	UserAgentHash        string
	TLSFingerprintHash   string
	HTTP2FingerprintHash string
	FirstSeenAt          int64
	LastSeenAt           int64
}

// UserDevicePatch contains only administrator-editable fields. Pointer
// fields preserve PATCH omission semantics.
type UserDevicePatch struct {
	Status *string
	Remark *string
}

// UserDeviceSummary is the safe list projection used by the administrator
// API. It intentionally has no compatibility or fingerprint HMAC fields.
type UserDeviceSummary struct {
	Id                int    `json:"id"`
	UserId            int    `json:"user_id"`
	Status            string `json:"status"`
	ClientFamily      string `json:"client_family"`
	OSFamily          string `json:"os_family"`
	Architecture      string `json:"architecture"`
	Originator        string `json:"originator"`
	Confidence        string `json:"confidence"`
	FirstSeenAt       int64  `json:"first_seen_at"`
	LastSeenAt        int64  `json:"last_seen_at"`
	FirstIP           string `json:"first_ip"`
	LastIP            string `json:"last_ip"`
	ObservedIPCount   int    `json:"observed_ip_count"`
	RequestCount      int64  `json:"request_count"`
	DeniedCount       int64  `json:"denied_count"`
	LastClientVersion string `json:"last_client_version"`
	Remark            string `json:"remark"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
	FingerprintCount  int64  `json:"fingerprint_count"`
	RecentIPCount     int64  `json:"recent_ip_count"`
}

// UserDeviceQuery describes the user-scoped list query used by the model
// layer. The exported ListUserDevices function keeps the existing compact
// signature for callers while normalizing into this type internally.
type UserDeviceQuery struct {
	UserId int
	Status string
	Page   *common.PageInfo
}

// UserDeviceDetail combines the safe device projection with aliases and the
// ten most recent IP rows. Hash fields remain excluded by their JSON tags.
type UserDeviceDetail struct {
	Device       UserDevice              `json:"device"`
	Fingerprints []UserDeviceFingerprint `json:"fingerprints"`
	RecentIPs    []UserDeviceIP          `json:"recent_ips"`
}

// UserDeviceStatsUpdate is the batch persistence boundary used by the service
// ticker. A caller should aggregate requests before passing updates here.
type UserDeviceStatsUpdate struct {
	UserId        int
	DeviceId      int
	FingerprintId int
	RequestCount  int64
	DeniedCount   int64
	LastSeenAt    int64
	ClientVersion string
	IPHash        string
	IP            string
}

func validateUserDeviceHash(value, name string, required bool) error {
	if value == "" {
		if required {
			return fmt.Errorf("%s is empty", name)
		}
		return nil
	}
	if len(value) > 64 {
		return fmt.Errorf("%s is too long", name)
	}
	return nil
}

func normalizeDeviceStatus(status string) (string, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return string(constant.UserDevicePending), nil
	}
	if !constant.IsValidUserDeviceStatus(status) {
		return "", ErrInvalidUserDeviceStatus
	}
	return status, nil
}

func normalizeFingerprintStatus(status string) (string, error) {
	status = strings.TrimSpace(status)
	if status == "" {
		return string(constant.DeviceFingerprintPending), nil
	}
	if !constant.IsValidUserDeviceFingerprintStatus(status) {
		return "", ErrInvalidUserDeviceFingerprintStatus
	}
	return status, nil
}

func normalizeObservationTimes(now, firstSeen int64) (int64, int64) {
	if now <= 0 {
		now = time.Now().Unix()
	}
	if firstSeen <= 0 {
		firstSeen = now
	}
	return now, firstSeen
}

func setFingerprintShortID(fingerprint *UserDeviceFingerprint) {
	if fingerprint == nil {
		return
	}
	shortLength := 12
	if len(fingerprint.FingerprintHash) < shortLength {
		shortLength = len(fingerprint.FingerprintHash)
	}
	fingerprint.ShortId = fingerprint.FingerprintHash[:shortLength]
}

func findUserDeviceFingerprintWithTx(tx *gorm.DB, userId int, fingerprintHash string) (*UserDeviceFingerprint, error) {
	var fingerprint UserDeviceFingerprint
	err := lockForUpdate(tx).Where("user_id = ? AND fingerprint_hash = ?", userId, fingerprintHash).First(&fingerprint).Error
	if err != nil {
		return nil, err
	}
	setFingerprintShortID(&fingerprint)
	return &fingerprint, nil
}

func findUserDeviceWithTx(tx *gorm.DB, userId, deviceId int) (*UserDevice, error) {
	var device UserDevice
	if err := lockForUpdate(tx).Where("user_id = ? AND id = ?", userId, deviceId).First(&device).Error; err != nil {
		return nil, err
	}
	return &device, nil
}

func lockUserDeviceOwnerWithTx(tx *gorm.DB, userId int) error {
	var user User
	return lockForUpdate(tx.Unscoped()).Select("id").Where("id = ?", userId).First(&user).Error
}

// FindUserDeviceFingerprint returns an alias and its owning device. Both
// reads include user_id so a caller cannot accidentally cross tenant data.
func FindUserDeviceFingerprint(userId int, fingerprintHash string) (*UserDeviceFingerprint, *UserDevice, error) {
	if userId <= 0 {
		return nil, nil, errors.New("invalid user id")
	}
	if err := validateUserDeviceHash(fingerprintHash, "fingerprint hash", true); err != nil {
		return nil, nil, err
	}
	var fingerprint UserDeviceFingerprint
	if err := DB.Where("user_id = ? AND fingerprint_hash = ?", userId, fingerprintHash).First(&fingerprint).Error; err != nil {
		return nil, nil, err
	}
	setFingerprintShortID(&fingerprint)
	var device UserDevice
	if err := DB.Where("user_id = ? AND id = ?", userId, fingerprint.DeviceId).First(&device).Error; err != nil {
		return nil, nil, err
	}
	return &fingerprint, &device, nil
}

// FindCompatibleAllowedDevices returns stable, user-scoped candidates for
// upgrade association. Fingerprint trust is checked by the decision layer.
func FindCompatibleAllowedDevices(userId int, compatibilityHash string) ([]UserDevice, error) {
	if userId <= 0 {
		return nil, errors.New("invalid user id")
	}
	if err := validateUserDeviceHash(compatibilityHash, "compatibility hash", true); err != nil {
		return nil, err
	}
	var devices []UserDevice
	err := DB.Where("user_id = ? AND compatibility_hash = ? AND status = ?", userId, compatibilityHash, string(constant.UserDeviceAllowed)).
		Order("id ASC").Find(&devices).Error
	return devices, err
}

func updateObservedDeviceWithTx(tx *gorm.DB, device *UserDevice, input CreateUserDeviceInput, now int64) error {
	updates := make(map[string]interface{})
	if now > device.LastSeenAt {
		updates["last_seen_at"] = now
	}
	if input.ClientFamily != "" {
		updates["client_family"] = input.ClientFamily
	}
	if input.OSFamily != "" {
		updates["os_family"] = input.OSFamily
	}
	if input.Architecture != "" {
		updates["architecture"] = input.Architecture
	}
	if input.Originator != "" {
		updates["originator"] = input.Originator
	}
	if input.Confidence != "" {
		updates["confidence"] = input.Confidence
	}
	if input.ClientVersion != "" {
		updates["last_client_version"] = input.ClientVersion
	}
	if input.IP != "" {
		updates["last_ip"] = input.IP
	}
	if input.RequestCount > 0 {
		updates["request_count"] = gorm.Expr("request_count + ?", input.RequestCount)
	}
	if input.DeniedCount > 0 {
		updates["denied_count"] = gorm.Expr("denied_count + ?", input.DeniedCount)
	}
	if len(updates) > 0 {
		if err := tx.Model(&UserDevice{}).Where("user_id = ? AND id = ?", device.UserId, device.Id).Updates(updates).Error; err != nil {
			return err
		}
	}
	if input.IPHash == "" && input.IP == "" {
		return nil
	}
	if input.IPHash == "" || input.IP == "" {
		return errors.New("IP hash and IP must be provided together")
	}
	return upsertUserDeviceIPWithTx(tx, device.UserId, device.Id, input.IPHash, input.IP, now, input.RequestCount)
}

func upsertUserDeviceIPWithTx(tx *gorm.DB, userId, deviceId int, ipHash, ip string, now, requestCount int64) error {
	if userId <= 0 || deviceId <= 0 {
		return errors.New("invalid user device IP owner")
	}
	if err := validateUserDeviceHash(ipHash, "IP hash", true); err != nil {
		return err
	}
	if ip == "" || len(ip) > 45 {
		return errors.New("invalid IP")
	}
	if now <= 0 {
		now = time.Now().Unix()
	}
	var row UserDeviceIP
	err := lockForUpdate(tx).Where("user_id = ? AND device_id = ? AND ip_hash = ?", userId, deviceId, ipHash).First(&row).Error
	if err == nil {
		updates := map[string]interface{}{}
		if now > row.LastSeenAt {
			updates["last_seen_at"] = now
		}
		if requestCount > 0 {
			updates["request_count"] = gorm.Expr("request_count + ?", requestCount)
		}
		if len(updates) > 0 {
			return tx.Model(&UserDeviceIP{}).Where("user_id = ? AND device_id = ? AND id = ?", userId, deviceId, row.Id).Updates(updates).Error
		}
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if requestCount <= 0 {
		requestCount = 1
	}
	row = UserDeviceIP{
		UserId: userId, DeviceId: deviceId, IPHash: ipHash, IP: ip,
		FirstSeenAt: now, LastSeenAt: now, RequestCount: requestCount,
	}
	result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		if err := lockForUpdate(tx).Where("user_id = ? AND device_id = ? AND ip_hash = ?", userId, deviceId, ipHash).First(&row).Error; err != nil {
			return err
		}
		setCount := requestCount
		updates := map[string]interface{}{"request_count": gorm.Expr("request_count + ?", setCount)}
		if now > row.LastSeenAt {
			updates["last_seen_at"] = now
		}
		if err := tx.Model(&UserDeviceIP{}).Where("user_id = ? AND device_id = ? AND id = ?", userId, deviceId, row.Id).Updates(updates).Error; err != nil {
			return err
		}
	} else if err := tx.Model(&UserDevice{}).Where("user_id = ? AND id = ?", userId, deviceId).
		UpdateColumn("observed_ip_count", gorm.Expr("observed_ip_count + ?", 1)).Error; err != nil {
		return err
	}

	var count int64
	if err := tx.Model(&UserDeviceIP{}).Where("user_id = ? AND device_id = ?", userId, deviceId).Count(&count).Error; err != nil {
		return err
	}
	if count <= maxUserDeviceIPs {
		return nil
	}
	var stale []UserDeviceIP
	if err := tx.Where("user_id = ? AND device_id = ?", userId, deviceId).
		Order("last_seen_at ASC").Order("id ASC").Limit(int(count - maxUserDeviceIPs)).Find(&stale).Error; err != nil {
		return err
	}
	for _, old := range stale {
		if err := tx.Unscoped().Where("user_id = ? AND device_id = ? AND id = ?", userId, deviceId, old.Id).Delete(&UserDeviceIP{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func createObservedUserDeviceOnce(input CreateUserDeviceInput) (*UserDevice, *UserDeviceFingerprint, error) {
	if input.UserId <= 0 {
		return nil, nil, errors.New("invalid user id")
	}
	if err := validateUserDeviceHash(input.FingerprintHash, "fingerprint hash", true); err != nil {
		return nil, nil, err
	}
	if err := validateUserDeviceHash(input.CompatibilityHash, "compatibility hash", true); err != nil {
		return nil, nil, err
	}
	if err := validateUserDeviceHash(input.UserAgentHash, "user agent hash", false); err != nil {
		return nil, nil, err
	}
	if err := validateUserDeviceHash(input.TLSFingerprintHash, "TLS fingerprint hash", false); err != nil {
		return nil, nil, err
	}
	if err := validateUserDeviceHash(input.HTTP2FingerprintHash, "HTTP/2 fingerprint hash", false); err != nil {
		return nil, nil, err
	}
	if input.IPHash != "" || input.IP != "" {
		if input.IPHash == "" || input.IP == "" {
			return nil, nil, errors.New("IP hash and IP must be provided together")
		}
		if len(input.IP) > 45 {
			return nil, nil, errors.New("invalid IP")
		}
	}
	status, err := normalizeDeviceStatus(input.Status)
	if err != nil {
		return nil, nil, err
	}
	now, firstSeenAt := normalizeObservationTimes(input.Now, input.FirstSeenAt)
	if input.RequestCount < 0 || input.DeniedCount < 0 {
		return nil, nil, errors.New("invalid user device counters")
	}

	var resultDevice *UserDevice
	var resultFingerprint *UserDeviceFingerprint
	err = DB.Transaction(func(tx *gorm.DB) error {
		// Serialize the per-user capacity check before locking a possibly absent
		// fingerprint. This consistent order avoids MySQL gap-lock deadlocks and
		// makes later locking reads see a concurrently committed alias.
		if err := lockUserDeviceOwnerWithTx(tx, input.UserId); err != nil {
			return err
		}
		existingFingerprint, findErr := findUserDeviceFingerprintWithTx(tx, input.UserId, input.FingerprintHash)
		if findErr == nil {
			device, err := findUserDeviceWithTx(tx, input.UserId, existingFingerprint.DeviceId)
			if err != nil {
				return err
			}
			if err := updateObservedDeviceWithTx(tx, device, input, now); err != nil {
				return err
			}
			resultDevice = device
			resultFingerprint = existingFingerprint
			return nil
		}
		if !errors.Is(findErr, gorm.ErrRecordNotFound) {
			return findErr
		}

		var deviceCount int64
		if err := tx.Model(&UserDevice{}).Where("user_id = ?", input.UserId).Count(&deviceCount).Error; err != nil {
			return err
		}
		if deviceCount >= maxUserDevices {
			return ErrUserDeviceLimit
		}
		device := &UserDevice{
			UserId: input.UserId, Status: status, CompatibilityHash: input.CompatibilityHash,
			ClientFamily: input.ClientFamily, OSFamily: input.OSFamily,
			Architecture: input.Architecture, Originator: input.Originator,
			Confidence: input.Confidence, FirstSeenAt: firstSeenAt, LastSeenAt: now,
			FirstIP: input.IP, LastIP: input.IP, RequestCount: input.RequestCount,
			DeniedCount: input.DeniedCount, LastClientVersion: input.ClientVersion,
		}
		if device.RequestCount == 0 {
			device.RequestCount = 1
		}
		if err := tx.Create(device).Error; err != nil {
			return err
		}
		fingerprint := &UserDeviceFingerprint{
			UserId: input.UserId, DeviceId: device.Id, FingerprintHash: input.FingerprintHash,
			CompatibilityHash: input.CompatibilityHash, Status: string(constant.DeviceFingerprintPending),
			ClientVersion: input.ClientVersion, UserAgentHash: input.UserAgentHash,
			TLSFingerprintHash: input.TLSFingerprintHash, HTTP2FingerprintHash: input.HTTP2FingerprintHash,
			FirstSeenAt: firstSeenAt, LastSeenAt: now, RequestCount: device.RequestCount,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(fingerprint).Error; err != nil {
			return err
		}

		storedFingerprint, readErr := findUserDeviceFingerprintWithTx(tx, input.UserId, input.FingerprintHash)
		if readErr != nil {
			return readErr
		}
		if storedFingerprint.DeviceId != device.Id {
			// The unique conflict belongs to another transaction's device.
			// Remove this transaction's orphan and return the committed owner.
			if err := tx.Unscoped().Where("user_id = ? AND device_id = ?", input.UserId, device.Id).Delete(&UserDeviceIP{}).Error; err != nil {
				return err
			}
			if err := tx.Unscoped().Where("user_id = ? AND id = ?", input.UserId, device.Id).Delete(&UserDevice{}).Error; err != nil {
				return err
			}
			owner, err := findUserDeviceWithTx(tx, input.UserId, storedFingerprint.DeviceId)
			if err != nil {
				return err
			}
			if err := updateObservedDeviceWithTx(tx, owner, input, now); err != nil {
				return err
			}
			resultDevice = owner
			resultFingerprint = storedFingerprint
			return nil
		}
		if input.IPHash != "" {
			if err := upsertUserDeviceIPWithTx(tx, input.UserId, device.Id, input.IPHash, input.IP, now, device.RequestCount); err != nil {
				return err
			}
		}
		setFingerprintShortID(fingerprint)
		resultDevice = device
		resultFingerprint = fingerprint
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return resultDevice, resultFingerprint, nil
}

// CreateObservedUserDevice creates or reuses a user-scoped logical device.
// The unique fingerprint index plus conflict reread makes concurrent first
// observations converge on one alias instead of surfacing a database error.
func CreateObservedUserDevice(input CreateUserDeviceInput) (*UserDevice, *UserDeviceFingerprint, error) {
	for range 3 {
		device, fingerprint, err := createObservedUserDeviceOnce(input)
		if err == nil {
			return device, fingerprint, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, err
		}
	}
	return nil, nil, gorm.ErrRecordNotFound
}

// AttachUserDeviceFingerprint adds an alias to an existing device. A
// duplicate alias is idempotent when it names the same device and is rejected
// with a stable conflict error when it names another one.
func AttachUserDeviceFingerprint(input AttachFingerprintInput) (*UserDeviceFingerprint, error) {
	if input.UserId <= 0 || input.DeviceId <= 0 {
		return nil, errors.New("invalid user device owner")
	}
	if err := validateUserDeviceHash(input.FingerprintHash, "fingerprint hash", true); err != nil {
		return nil, err
	}
	if err := validateUserDeviceHash(input.CompatibilityHash, "compatibility hash", true); err != nil {
		return nil, err
	}
	if err := validateUserDeviceHash(input.UserAgentHash, "user agent hash", false); err != nil {
		return nil, err
	}
	if err := validateUserDeviceHash(input.TLSFingerprintHash, "TLS fingerprint hash", false); err != nil {
		return nil, err
	}
	if err := validateUserDeviceHash(input.HTTP2FingerprintHash, "HTTP/2 fingerprint hash", false); err != nil {
		return nil, err
	}
	status, err := normalizeFingerprintStatus(input.Status)
	if err != nil {
		return nil, err
	}
	now := input.LastSeenAt
	if now <= 0 {
		now = time.Now().Unix()
	}
	firstSeenAt := input.FirstSeenAt
	if firstSeenAt <= 0 {
		firstSeenAt = now
	}
	var result *UserDeviceFingerprint
	err = DB.Transaction(func(tx *gorm.DB) error {
		if err := lockUserDeviceOwnerWithTx(tx, input.UserId); err != nil {
			return err
		}
		if _, err := findUserDeviceWithTx(tx, input.UserId, input.DeviceId); err != nil {
			return err
		}
		if existing, err := findUserDeviceFingerprintWithTx(tx, input.UserId, input.FingerprintHash); err == nil {
			if existing.DeviceId != input.DeviceId {
				return ErrUserDeviceFingerprintConflict
			}
			result = existing
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var aliasCount int64
		if err := tx.Model(&UserDeviceFingerprint{}).Where("user_id = ? AND device_id = ?", input.UserId, input.DeviceId).Count(&aliasCount).Error; err != nil {
			return err
		}
		if aliasCount >= maxUserDeviceFingerprints {
			return ErrUserDeviceFingerprintLimit
		}
		fingerprint := &UserDeviceFingerprint{
			UserId: input.UserId, DeviceId: input.DeviceId, FingerprintHash: input.FingerprintHash,
			CompatibilityHash: input.CompatibilityHash, Status: status, GraceUntil: input.GraceUntil,
			ClientVersion: input.ClientVersion, UserAgentHash: input.UserAgentHash,
			TLSFingerprintHash: input.TLSFingerprintHash, HTTP2FingerprintHash: input.HTTP2FingerprintHash,
			FirstSeenAt: firstSeenAt, LastSeenAt: now,
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(fingerprint).Error; err != nil {
			return err
		}
		stored, err := findUserDeviceFingerprintWithTx(tx, input.UserId, input.FingerprintHash)
		if err != nil {
			return err
		}
		if stored.DeviceId != input.DeviceId {
			return ErrUserDeviceFingerprintConflict
		}
		result = stored
		return nil
	})
	return result, err
}

func toUserDeviceSummary(device UserDevice, fingerprintCount, recentIPCount int64) UserDeviceSummary {
	return UserDeviceSummary{
		Id: device.Id, UserId: device.UserId, Status: device.Status, ClientFamily: device.ClientFamily,
		OSFamily: device.OSFamily, Architecture: device.Architecture, Originator: device.Originator,
		Confidence: device.Confidence, FirstSeenAt: device.FirstSeenAt, LastSeenAt: device.LastSeenAt,
		FirstIP: device.FirstIP, LastIP: device.LastIP, ObservedIPCount: device.ObservedIPCount,
		RequestCount: device.RequestCount, DeniedCount: device.DeniedCount,
		LastClientVersion: device.LastClientVersion, Remark: device.Remark,
		CreatedAt: device.CreatedAt, UpdatedAt: device.UpdatedAt,
		FingerprintCount: fingerprintCount, RecentIPCount: recentIPCount,
	}
}

// ListUserDevices returns a stable page ordered by last observation and ID.
func ListUserDevices(userId int, status string, page *common.PageInfo) ([]UserDeviceSummary, int64, error) {
	queryOptions := UserDeviceQuery{UserId: userId, Status: status, Page: page}
	if queryOptions.UserId <= 0 {
		return nil, 0, errors.New("invalid user id")
	}
	status = strings.TrimSpace(queryOptions.Status)
	if status != "" && !constant.IsValidUserDeviceStatus(status) {
		return nil, 0, ErrInvalidUserDeviceStatus
	}
	pageNumber, pageSize := 1, common.ItemsPerPage
	if queryOptions.Page != nil {
		if queryOptions.Page.Page > 0 {
			pageNumber = queryOptions.Page.Page
		}
		if queryOptions.Page.PageSize > 0 {
			pageSize = queryOptions.Page.PageSize
		}
	}
	if pageSize > 100 {
		pageSize = 100
	}
	if pageSize < 1 {
		pageSize = common.ItemsPerPage
	}
	query := DB.Model(&UserDevice{}).Where("user_id = ?", userId)
	if status != "" {
		query = query.Where("status = ?", status)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var devices []UserDevice
	if err := query.Order("last_seen_at DESC").Order("id DESC").Limit(pageSize).Offset((pageNumber - 1) * pageSize).Find(&devices).Error; err != nil {
		return nil, 0, err
	}
	type deviceCount struct {
		DeviceId int   `gorm:"column:device_id"`
		Total    int64 `gorm:"column:total"`
	}
	deviceIDs := make([]int, 0, len(devices))
	for _, device := range devices {
		deviceIDs = append(deviceIDs, device.Id)
	}
	fingerprintCounts := make(map[int]int64, len(devices))
	recentIPCounts := make(map[int]int64, len(devices))
	if len(deviceIDs) > 0 {
		var fingerprintRows []deviceCount
		if err := DB.Model(&UserDeviceFingerprint{}).
			Select("device_id, COUNT(*) AS total").
			Where("user_id = ? AND device_id IN ?", userId, deviceIDs).
			Group("device_id").
			Find(&fingerprintRows).Error; err != nil {
			return nil, 0, err
		}
		for _, row := range fingerprintRows {
			fingerprintCounts[row.DeviceId] = row.Total
		}
		var recentIPRows []deviceCount
		if err := DB.Model(&UserDeviceIP{}).
			Select("device_id, COUNT(*) AS total").
			Where("user_id = ? AND device_id IN ?", userId, deviceIDs).
			Group("device_id").
			Find(&recentIPRows).Error; err != nil {
			return nil, 0, err
		}
		for _, row := range recentIPRows {
			recentIPCounts[row.DeviceId] = row.Total
		}
	}
	summaries := make([]UserDeviceSummary, 0, len(devices))
	for _, device := range devices {
		summaries = append(summaries, toUserDeviceSummary(device, fingerprintCounts[device.Id], recentIPCounts[device.Id]))
	}
	return summaries, total, nil
}

// GetUserDeviceDetail loads one user-owned device and its safe detail rows.
func GetUserDeviceDetail(userId int, deviceId int) (*UserDeviceDetail, error) {
	if userId <= 0 || deviceId <= 0 {
		return nil, errors.New("invalid user device owner")
	}
	var device UserDevice
	if err := DB.Where("user_id = ? AND id = ?", userId, deviceId).First(&device).Error; err != nil {
		return nil, err
	}
	fingerprints := make([]UserDeviceFingerprint, 0)
	if err := DB.Where("user_id = ? AND device_id = ?", userId, deviceId).Order("id ASC").Find(&fingerprints).Error; err != nil {
		return nil, err
	}
	for i := range fingerprints {
		setFingerprintShortID(&fingerprints[i])
	}
	recentIPs := make([]UserDeviceIP, 0, recentUserDeviceIPs)
	if err := DB.Where("user_id = ? AND device_id = ?", userId, deviceId).
		Order("last_seen_at DESC").Order("id DESC").Limit(recentUserDeviceIPs).Find(&recentIPs).Error; err != nil {
		return nil, err
	}
	return &UserDeviceDetail{Device: device, Fingerprints: fingerprints, RecentIPs: recentIPs}, nil
}

// UpdateUserDevice applies an administrator patch and versions actual device
// or alias state changes. An allowed device trusts pending/grace aliases while
// leaving explicit blocked aliases untouched.
func UpdateUserDevice(userId int, deviceId int, patch UserDevicePatch) error {
	if userId <= 0 || deviceId <= 0 {
		return errors.New("invalid user device owner")
	}
	if patch.Status == nil && patch.Remark == nil {
		return nil
	}
	if patch.Remark != nil && utf8.RuneCountInString(*patch.Remark) > 255 {
		return errors.New("device remark is too long")
	}
	var versionChanged bool
	err := DB.Transaction(func(tx *gorm.DB) error {
		if err := lockUserDeviceOwnerWithTx(tx, userId); err != nil {
			return err
		}
		device, err := findUserDeviceWithTx(tx, userId, deviceId)
		if err != nil {
			return err
		}
		updates := make(map[string]interface{})
		if patch.Remark != nil {
			updates["remark"] = *patch.Remark
		}
		statusChanged := false
		newStatus := device.Status
		if patch.Status != nil {
			newStatus = strings.TrimSpace(*patch.Status)
			if !constant.IsValidUserDeviceStatus(newStatus) {
				return ErrInvalidUserDeviceStatus
			}
			if newStatus != device.Status {
				statusChanged = true
				updates["status"] = newStatus
			}
		}
		if len(updates) > 0 {
			if err := tx.Model(&UserDevice{}).Where("user_id = ? AND id = ?", userId, deviceId).Updates(updates).Error; err != nil {
				return err
			}
		}
		aliasChanged := false
		if newStatus == string(constant.UserDeviceAllowed) {
			result := tx.Model(&UserDeviceFingerprint{}).
				Where("user_id = ? AND device_id = ? AND status IN ?", userId, deviceId,
					[]string{string(constant.DeviceFingerprintPending), string(constant.DeviceFingerprintGrace)}).
				Update("status", string(constant.DeviceFingerprintTrusted))
			if result.Error != nil {
				return result.Error
			}
			aliasChanged = result.RowsAffected > 0
		}
		versionChanged = statusChanged || aliasChanged
		if !versionChanged {
			return nil
		}
		_, err = IncrementUserAccessPolicyVersionWithTx(tx, userId)
		return err
	})
	if err != nil {
		return err
	}
	if versionChanged {
		return PublishUserAccessPolicyCache(userId)
	}
	return nil
}

// UpdateUserDeviceFingerprint updates a manually reviewable alias. Grace is
// system-owned and therefore cannot be assigned by this administrator API.
func UpdateUserDeviceFingerprint(userId int, deviceId int, fingerprintId int, status string) error {
	if userId <= 0 || deviceId <= 0 || fingerprintId <= 0 {
		return errors.New("invalid user device fingerprint owner")
	}
	status = strings.TrimSpace(status)
	if status == string(constant.DeviceFingerprintGrace) || !constant.IsValidUserDeviceFingerprintStatus(status) {
		return ErrInvalidUserDeviceFingerprintStatus
	}
	var versionChanged bool
	err := DB.Transaction(func(tx *gorm.DB) error {
		if err := lockUserDeviceOwnerWithTx(tx, userId); err != nil {
			return err
		}
		var fingerprint UserDeviceFingerprint
		if err := lockForUpdate(tx).Where("user_id = ? AND device_id = ? AND id = ?", userId, deviceId, fingerprintId).First(&fingerprint).Error; err != nil {
			return err
		}
		if fingerprint.Status == status {
			return nil
		}
		if err := tx.Model(&UserDeviceFingerprint{}).Where("user_id = ? AND device_id = ? AND id = ?", userId, deviceId, fingerprintId).Update("status", status).Error; err != nil {
			return err
		}
		versionChanged = true
		_, err := IncrementUserAccessPolicyVersionWithTx(tx, userId)
		return err
	})
	if err != nil {
		return err
	}
	if versionChanged {
		return PublishUserAccessPolicyCache(userId)
	}
	return nil
}

// CountAllowedTrustedDevices counts devices that are both allowed and have a
// trusted alias. The join includes both user ownership columns.
func CountAllowedTrustedDevices(userId int) (int64, error) {
	if userId <= 0 {
		return 0, errors.New("invalid user id")
	}
	var count int64
	err := DB.Model(&UserDeviceFingerprint{}).
		Joins("JOIN user_devices ON user_devices.id = user_device_fingerprints.device_id AND user_devices.user_id = user_device_fingerprints.user_id").
		Where("user_device_fingerprints.user_id = ? AND user_devices.status = ? AND user_device_fingerprints.status = ?", userId, string(constant.UserDeviceAllowed), string(constant.DeviceFingerprintTrusted)).
		Distinct("user_device_fingerprints.device_id").Count(&count).Error
	return count, err
}

// DeleteStalePendingUserDevices removes only pending devices older than the
// retention boundary. Alias and IP rows are deleted before their device.
func DeleteStalePendingUserDevices(before int64) error {
	if before <= 0 {
		return nil
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		var stale []UserDevice
		if err := tx.Where("status = ? AND last_seen_at < ?", string(constant.UserDevicePending), before).Find(&stale).Error; err != nil {
			return err
		}
		for _, device := range stale {
			if err := tx.Unscoped().Where("user_id = ? AND device_id = ?", device.UserId, device.Id).Delete(&UserDeviceFingerprint{}).Error; err != nil {
				return err
			}
			if err := tx.Unscoped().Where("user_id = ? AND device_id = ?", device.UserId, device.Id).Delete(&UserDeviceIP{}).Error; err != nil {
				return err
			}
			if err := tx.Unscoped().Where("user_id = ? AND id = ?", device.UserId, device.Id).Delete(&UserDevice{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ApplyUserDeviceStats persists already aggregated counters in one
// transaction. It never changes AccessPolicyVersion.
func ApplyUserDeviceStats(updates []UserDeviceStatsUpdate) error {
	if len(updates) == 0 {
		return nil
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		for _, update := range updates {
			if update.UserId <= 0 || update.DeviceId <= 0 || update.RequestCount < 0 || update.DeniedCount < 0 {
				return errors.New("invalid user device statistics update")
			}
			if len(update.ClientVersion) > 64 {
				return errors.New("client version is too long")
			}
			device, err := findUserDeviceWithTx(tx, update.UserId, update.DeviceId)
			if err != nil {
				return err
			}
			deviceUpdates := make(map[string]interface{})
			if update.RequestCount > 0 {
				deviceUpdates["request_count"] = gorm.Expr("request_count + ?", update.RequestCount)
			}
			if update.DeniedCount > 0 {
				deviceUpdates["denied_count"] = gorm.Expr("denied_count + ?", update.DeniedCount)
			}
			if update.LastSeenAt > device.LastSeenAt {
				deviceUpdates["last_seen_at"] = update.LastSeenAt
			}
			if update.IP != "" {
				deviceUpdates["last_ip"] = update.IP
			}
			if update.ClientVersion != "" {
				deviceUpdates["last_client_version"] = update.ClientVersion
			}
			if len(deviceUpdates) > 0 {
				if err := tx.Model(&UserDevice{}).Where("user_id = ? AND id = ?", update.UserId, update.DeviceId).Updates(deviceUpdates).Error; err != nil {
					return err
				}
			}
			if update.FingerprintId > 0 {
				var fingerprint UserDeviceFingerprint
				if err := lockForUpdate(tx).Where("user_id = ? AND device_id = ? AND id = ?", update.UserId, update.DeviceId, update.FingerprintId).First(&fingerprint).Error; err != nil {
					return err
				}
				fingerprintUpdates := make(map[string]interface{})
				if update.RequestCount > 0 {
					fingerprintUpdates["request_count"] = gorm.Expr("request_count + ?", update.RequestCount)
				}
				if update.LastSeenAt > fingerprint.LastSeenAt {
					fingerprintUpdates["last_seen_at"] = update.LastSeenAt
				}
				if update.ClientVersion != "" {
					fingerprintUpdates["client_version"] = update.ClientVersion
				}
				if len(fingerprintUpdates) > 0 {
					if err := tx.Model(&UserDeviceFingerprint{}).Where("user_id = ? AND device_id = ? AND id = ?", update.UserId, update.DeviceId, update.FingerprintId).Updates(fingerprintUpdates).Error; err != nil {
						return err
					}
				}
			}
			if update.IPHash != "" || update.IP != "" {
				if update.IPHash == "" || update.IP == "" {
					return errors.New("IP hash and IP must be provided together")
				}
				if err := upsertUserDeviceIPWithTx(tx, update.UserId, update.DeviceId, update.IPHash, update.IP, update.LastSeenAt, update.RequestCount); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
