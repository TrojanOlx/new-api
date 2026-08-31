package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

const (
	userDeviceDecisionCacheTTL       = 5 * time.Minute
	userDeviceUntrackedCacheTTL      = 10 * time.Minute
	userDeviceUpgradeCandidateWindow = 7 * 24 * time.Hour
	userAccessWarningInterval        = time.Minute
	userDeviceDecisionCacheMax       = 10_000
)

type UserAccessDecision string

const (
	UserAccessAllow       UserAccessDecision = "allow"
	UserAccessDenyIP      UserAccessDecision = "deny_ip"
	UserAccessDenyDevice  UserAccessDecision = "deny_device"
	UserAccessDenyNetwork UserAccessDecision = "deny_network"
	UserAccessUnavailable UserAccessDecision = "unavailable"
)

type UserAccessResult struct {
	Decision      UserAccessDecision
	Reason        string
	DeviceId      int
	FingerprintId int
	RateLimitRPM  int
	BlockedModels []string
	Release       func()
}

type UserDeviceRequestControls = model.UserDeviceRequestControls

type userDeviceResolution struct {
	DeviceId                  int
	FingerprintId             int
	RateLimitRPM              int
	BlockedModels             []string
	DeviceStatus              string
	FingerprintStatus         string
	GraceUntil                int64
	Untracked                 bool
	InitialObservationCounted bool
}

type userAccessPolicyBackend interface {
	resolve(user *model.UserBase, evidence DeviceFingerprintEvidence, ipHash string, ip string, now time.Time) (userDeviceResolution, error)
	begin(userId, deviceId int, ipHash string, now time.Time, rejectOnConflict bool) (bool, func())
	record(update model.UserDeviceStatsUpdate)
	markFingerprintPending(userId, deviceId, fingerprintId int) error
}

type unavailableUserAccessBackend struct{}

func (unavailableUserAccessBackend) resolve(*model.UserBase, DeviceFingerprintEvidence, string, string, time.Time) (userDeviceResolution, error) {
	return userDeviceResolution{}, errors.New("user device backend is unavailable")
}

func (unavailableUserAccessBackend) begin(int, int, string, time.Time, bool) (bool, func()) {
	return false, nil
}

func (unavailableUserAccessBackend) record(model.UserDeviceStatsUpdate) {}

func (unavailableUserAccessBackend) markFingerprintPending(int, int, int) error {
	return errors.New("user device backend is unavailable")
}

type modelUserAccessBackend struct{}

type userDeviceResolutionCacheEntry struct {
	Resolution userDeviceResolution `json:"resolution"`
	ExpiresAt  int64                `json:"expires_at"`
}

type cachedUserIPMatcher struct {
	allowlist string
	version   int64
	matcher   *common.IPAllowlistMatcher
}

var (
	buildDeviceFingerprintForAccess                         = BuildDeviceFingerprint
	userAccessBackendForAccess      userAccessPolicyBackend = modelUserAccessBackend{}
	userIPMatcherMu                 sync.RWMutex
	userIPMatchers                  = make(map[int]cachedUserIPMatcher)
	userDeviceDecisionCacheMu       sync.Mutex
	userDeviceDecisionCache         = make(map[string]userDeviceResolutionCacheEntry)
	userAccessWarningMu             sync.Mutex
	userAccessLastWarning           time.Time
)

func userAccessWarn(now time.Time, message string) {
	if now.IsZero() {
		now = time.Now()
	}
	userAccessWarningMu.Lock()
	if !userAccessLastWarning.IsZero() && now.Sub(userAccessLastWarning) < userAccessWarningInterval {
		userAccessWarningMu.Unlock()
		return
	}
	userAccessLastWarning = now
	userAccessWarningMu.Unlock()
	common.SysError(message)
}

func userDeviceDecisionCacheKey(user *model.UserBase, fingerprintHash string) string {
	return strconv.Itoa(user.Id) + ":" + strconv.FormatInt(user.AccessPolicyVersion, 10) + ":" + fingerprintHash
}

func userDeviceDecisionRedisKey(key string) string {
	return "access:device:decision:v2:" + key
}

func getUserDeviceDecisionCache(user *model.UserBase, fingerprintHash string, now time.Time) (userDeviceResolution, bool) {
	key := userDeviceDecisionCacheKey(user, fingerprintHash)
	nowUnix := now.Unix()
	userDeviceDecisionCacheMu.Lock()
	entry, found := userDeviceDecisionCache[key]
	if found && entry.ExpiresAt <= nowUnix {
		delete(userDeviceDecisionCache, key)
		found = false
	}
	userDeviceDecisionCacheMu.Unlock()
	if found {
		return entry.Resolution, true
	}
	if !common.RedisEnabled || common.RDB == nil {
		return userDeviceResolution{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := common.RDB.Get(ctx, userDeviceDecisionRedisKey(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return userDeviceResolution{}, false
	}
	if err != nil {
		userAccessWarn(now, "user device decision Redis read failed; using local/database fallback: "+err.Error())
		return userDeviceResolution{}, false
	}
	if err := common.Unmarshal(raw, &entry); err != nil || entry.ExpiresAt <= nowUnix {
		return userDeviceResolution{}, false
	}
	userDeviceDecisionCacheMu.Lock()
	userDeviceDecisionCache[key] = entry
	userDeviceDecisionCacheMu.Unlock()
	return entry.Resolution, true
}

func setUserDeviceDecisionCache(user *model.UserBase, fingerprintHash string, resolution userDeviceResolution, now time.Time) {
	// This flag describes only the cold-path request that created the row. A
	// cache hit is a later request and must be included in the stats aggregate.
	resolution.InitialObservationCounted = false
	ttl := userDeviceDecisionCacheTTL
	if resolution.Untracked {
		ttl = userDeviceUntrackedCacheTTL
	} else if resolution.FingerprintStatus == string(constant.DeviceFingerprintGrace) {
		remaining := time.Unix(resolution.GraceUntil, 0).Sub(now)
		if remaining <= 0 {
			remaining = time.Second
		}
		if remaining < ttl {
			ttl = remaining
		}
	}
	key := userDeviceDecisionCacheKey(user, fingerprintHash)
	entry := userDeviceResolutionCacheEntry{Resolution: resolution, ExpiresAt: now.Add(ttl).Unix()}
	userDeviceDecisionCacheMu.Lock()
	if len(userDeviceDecisionCache) >= userDeviceDecisionCacheMax {
		for cachedKey, cachedEntry := range userDeviceDecisionCache {
			if cachedEntry.ExpiresAt <= now.Unix() || len(userDeviceDecisionCache) >= userDeviceDecisionCacheMax {
				delete(userDeviceDecisionCache, cachedKey)
			}
			if len(userDeviceDecisionCache) < userDeviceDecisionCacheMax {
				break
			}
		}
	}
	userDeviceDecisionCache[key] = entry
	userDeviceDecisionCacheMu.Unlock()
	if !common.RedisEnabled || common.RDB == nil {
		return
	}
	raw, err := common.Marshal(entry)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := common.RDB.Set(ctx, userDeviceDecisionRedisKey(key), raw, ttl).Err(); err != nil {
		userAccessWarn(now, "user device decision Redis write failed; using in-process cache: "+err.Error())
	}
}

func userDeviceResolutionFromRows(device *model.UserDevice, fingerprint *model.UserDeviceFingerprint) (userDeviceResolution, error) {
	controls, err := device.RequestControls()
	if err != nil {
		return userDeviceResolution{}, err
	}
	return userDeviceResolution{
		DeviceId: device.Id, FingerprintId: fingerprint.Id,
		RateLimitRPM: controls.RateLimitRPM, BlockedModels: controls.BlockedModels,
		DeviceStatus: device.Status, FingerprintStatus: fingerprint.Status,
		GraceUntil: fingerprint.GraceUntil,
	}, nil
}

func trustedUpgradeCandidate(device model.UserDevice, detail *model.UserDeviceDetail, now time.Time) bool {
	if device.LastSeenAt < now.Add(-userDeviceUpgradeCandidateWindow).Unix() || detail == nil {
		return false
	}
	for _, fingerprint := range detail.Fingerprints {
		if fingerprint.Status == string(constant.DeviceFingerprintTrusted) {
			return true
		}
	}
	return false
}

func (modelUserAccessBackend) resolve(user *model.UserBase, evidence DeviceFingerprintEvidence, ipHash string, ip string, now time.Time) (userDeviceResolution, error) {
	if cached, found := getUserDeviceDecisionCache(user, evidence.FingerprintHash, now); found {
		return cached, nil
	}
	fingerprint, device, err := model.FindUserDeviceFingerprint(user.Id, evidence.FingerprintHash)
	if err == nil {
		resolution, err := userDeviceResolutionFromRows(device, fingerprint)
		if err != nil {
			return userDeviceResolution{}, err
		}
		setUserDeviceDecisionCache(user, evidence.FingerprintHash, resolution, now)
		return resolution, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return userDeviceResolution{}, err
	}

	candidates, err := model.FindCompatibleAllowedDevices(user.Id, evidence.CompatibilityHash)
	if err != nil {
		return userDeviceResolution{}, err
	}
	eligible := make([]model.UserDevice, 0, len(candidates))
	details := make(map[int]*model.UserDeviceDetail, len(candidates))
	for _, candidate := range candidates {
		detail, detailErr := model.GetUserDeviceDetail(user.Id, candidate.Id)
		if detailErr != nil {
			return userDeviceResolution{}, detailErr
		}
		if trustedUpgradeCandidate(candidate, detail, now) {
			eligible = append(eligible, candidate)
			details[candidate.Id] = detail
		}
	}

	var candidate *model.UserDevice
	if len(eligible) == 1 {
		candidate = &eligible[0]
	} else if len(eligible) > 1 {
		matching := make([]model.UserDevice, 0, len(eligible))
		for _, item := range eligible {
			for _, recentIP := range details[item.Id].RecentIPs {
				if recentIP.IPHash == ipHash {
					matching = append(matching, item)
					break
				}
			}
		}
		if len(matching) == 1 {
			candidate = &matching[0]
		}
	}

	if candidate != nil && !HasDeviceNetworkConflict(user.Id, candidate.Id, ipHash, now) {
		graceUntil := now.Add(time.Duration(common.DeviceUpgradeGraceHours) * time.Hour).Unix()
		fingerprint, err = model.AttachUserDeviceFingerprint(model.AttachFingerprintInput{
			UserId: user.Id, DeviceId: candidate.Id,
			FingerprintHash: evidence.FingerprintHash, CompatibilityHash: evidence.CompatibilityHash,
			Status: string(constant.DeviceFingerprintGrace), GraceUntil: graceUntil,
			ClientVersion: evidence.ClientVersion, RuntimeFamily: &evidence.RuntimeFamily,
			InstallationIDPresent: &evidence.InstallationIDPresent, WindowIDPresent: &evidence.WindowIDPresent,
			UserAgentHash:      evidence.UserAgentHash,
			TLSFingerprintHash: evidence.TLSFingerprintHash, HTTP2FingerprintHash: evidence.HTTP2FingerprintHash,
			FirstSeenAt: now.Unix(), LastSeenAt: now.Unix(),
		})
		if err == nil {
			resolution, err := userDeviceResolutionFromRows(candidate, fingerprint)
			if err != nil {
				return userDeviceResolution{}, err
			}
			setUserDeviceDecisionCache(user, evidence.FingerprintHash, resolution, now)
			return resolution, nil
		}
		if errors.Is(err, model.ErrUserDeviceLimit) || errors.Is(err, model.ErrUserDeviceFingerprintLimit) {
			resolution := userDeviceResolution{Untracked: true}
			setUserDeviceDecisionCache(user, evidence.FingerprintHash, resolution, now)
			return resolution, nil
		}
		if !errors.Is(err, model.ErrUserDeviceFingerprintConflict) {
			return userDeviceResolution{}, err
		}
		fingerprint, device, err = model.FindUserDeviceFingerprint(user.Id, evidence.FingerprintHash)
		if err == nil {
			resolution, err := userDeviceResolutionFromRows(device, fingerprint)
			if err != nil {
				return userDeviceResolution{}, err
			}
			setUserDeviceDecisionCache(user, evidence.FingerprintHash, resolution, now)
			return resolution, nil
		}
		return userDeviceResolution{}, err
	}

	device, fingerprint, err = model.CreateObservedUserDevice(model.CreateUserDeviceInput{
		UserId: user.Id, FingerprintHash: evidence.FingerprintHash, CompatibilityHash: evidence.CompatibilityHash,
		Status: string(constant.UserDevicePending), ClientFamily: evidence.ClientFamily,
		ClientVersion: evidence.ClientVersion, OSFamily: evidence.OSFamily, Architecture: evidence.Architecture,
		Originator: evidence.Originator, Confidence: evidence.Confidence,
		RuntimeFamily:         &evidence.RuntimeFamily,
		InstallationIDPresent: &evidence.InstallationIDPresent, WindowIDPresent: &evidence.WindowIDPresent,
		UserAgentHash: evidence.UserAgentHash, TLSFingerprintHash: evidence.TLSFingerprintHash,
		HTTP2FingerprintHash: evidence.HTTP2FingerprintHash,
		IPHash:               ipHash, IP: ip, FirstSeenAt: now.Unix(), Now: now.Unix(), RequestCount: 1,
	})
	if errors.Is(err, model.ErrUserDeviceLimit) || errors.Is(err, model.ErrUserDeviceFingerprintLimit) {
		resolution := userDeviceResolution{Untracked: true}
		setUserDeviceDecisionCache(user, evidence.FingerprintHash, resolution, now)
		return resolution, nil
	}
	if err != nil {
		return userDeviceResolution{}, err
	}
	resolution, err := userDeviceResolutionFromRows(device, fingerprint)
	if err != nil {
		return userDeviceResolution{}, err
	}
	resolution.InitialObservationCounted = true
	setUserDeviceDecisionCache(user, evidence.FingerprintHash, resolution, now)
	return resolution, nil
}

func (modelUserAccessBackend) begin(userId, deviceId int, ipHash string, now time.Time, rejectOnConflict bool) (bool, func()) {
	return BeginDeviceNetworkActivity(userId, deviceId, ipHash, now, rejectOnConflict)
}

func (modelUserAccessBackend) record(update model.UserDeviceStatsUpdate) {
	RecordDeviceAccessStat(update)
}

func (modelUserAccessBackend) markFingerprintPending(userId, deviceId, fingerprintId int) error {
	return model.UpdateUserDeviceFingerprint(userId, deviceId, fingerprintId, string(constant.DeviceFingerprintPending))
}

func matchUserIPPolicy(user *model.UserBase, clientIP netip.Addr) (bool, error) {
	if user.APIIPMode == string(constant.UserIPPolicyUnrestricted) {
		return true, nil
	}
	if user.APIIPMode != string(constant.UserIPPolicyAllowlist) {
		return false, fmt.Errorf("invalid user IP policy mode %q", user.APIIPMode)
	}

	userIPMatcherMu.RLock()
	cached, found := userIPMatchers[user.Id]
	userIPMatcherMu.RUnlock()
	if found && cached.version == user.AccessPolicyVersion && cached.allowlist == user.APIIPAllowlist {
		return cached.matcher.Match(clientIP), nil
	}

	var entries []string
	if err := common.Unmarshal([]byte(user.APIIPAllowlist), &entries); err != nil {
		return false, err
	}
	normalized, err := common.NormalizeIPAllowlist(entries)
	if err != nil {
		return false, err
	}
	if len(normalized) == 0 {
		return false, common.ErrUserIPAllowlistEmpty
	}
	matcher, err := common.CompileIPAllowlist(normalized)
	if err != nil {
		return false, err
	}

	userIPMatcherMu.Lock()
	userIPMatchers[user.Id] = cachedUserIPMatcher{
		allowlist: user.APIIPAllowlist,
		version:   user.AccessPolicyVersion,
		matcher:   matcher,
	}
	userIPMatcherMu.Unlock()
	return matcher.Match(clientIP), nil
}

func userDeviceDeniedResult(backend userAccessPolicyBackend, user *model.UserBase, resolution userDeviceResolution, evidence DeviceFingerprintEvidence, now time.Time, reason string) UserAccessResult {
	if resolution.DeviceId > 0 {
		requestCount := int64(1)
		if resolution.InitialObservationCounted {
			requestCount = 0
		}
		backend.record(model.UserDeviceStatsUpdate{
			UserId: user.Id, DeviceId: resolution.DeviceId, FingerprintId: resolution.FingerprintId,
			RequestCount: requestCount, DeniedCount: 1, LastSeenAt: now.Unix(), ClientVersion: evidence.ClientVersion,
		})
	}
	return UserAccessResult{
		Decision: UserAccessDenyDevice, Reason: reason,
		DeviceId: resolution.DeviceId, FingerprintId: resolution.FingerprintId,
		RateLimitRPM: resolution.RateLimitRPM, BlockedModels: resolution.BlockedModels,
	}
}

func EvaluateUserAPIAccess(user *model.UserBase, clientIP netip.Addr, meta DeviceRequestMetadata, now time.Time) UserAccessResult {
	if user == nil {
		return UserAccessResult{Decision: UserAccessUnavailable, Reason: "user_access_policy_unavailable"}
	}
	allowedIP, err := matchUserIPPolicy(user, clientIP)
	if err != nil {
		return UserAccessResult{Decision: UserAccessUnavailable, Reason: "ip_policy_unavailable"}
	}
	if !allowedIP {
		return UserAccessResult{Decision: UserAccessDenyIP, Reason: "ip_not_allowed"}
	}

	mode := constant.UserDevicePolicyMode(user.DevicePolicyMode)
	if mode == constant.UserDevicePolicyOff {
		if user.DeviceControlsEnabled {
			return UserAccessResult{Decision: UserAccessUnavailable, Reason: "access_control_unavailable"}
		}
		return UserAccessResult{Decision: UserAccessAllow}
	}
	if !constant.IsValidUserDevicePolicyMode(user.DevicePolicyMode) {
		return UserAccessResult{Decision: UserAccessUnavailable, Reason: "device_policy_unavailable"}
	}

	evidence, err := buildDeviceFingerprintForAccess(meta)
	if err != nil {
		if user.DeviceControlsEnabled {
			return UserAccessResult{Decision: UserAccessUnavailable, Reason: "access_control_unavailable"}
		}
		if mode == constant.UserDevicePolicyAllowlist {
			return UserAccessResult{Decision: UserAccessUnavailable, Reason: "device_fingerprint_unavailable"}
		}
		userAccessWarn(now, "user device fingerprint unavailable; access policy degraded open: "+err.Error())
		return UserAccessResult{Decision: UserAccessAllow}
	}

	canonicalIP := clientIP.Unmap().String()
	ipHash := common.GenerateHMACWithKey([]byte("device-ip-v1:"+common.DeviceFingerprintSecret), canonicalIP)
	resolution, err := userAccessBackendForAccess.resolve(user, evidence, ipHash, canonicalIP, now)
	if err != nil {
		if user.DeviceControlsEnabled {
			return UserAccessResult{Decision: UserAccessUnavailable, Reason: "access_control_unavailable"}
		}
		if mode == constant.UserDevicePolicyAllowlist {
			return UserAccessResult{Decision: UserAccessUnavailable, Reason: "device_policy_unavailable"}
		}
		userAccessWarn(now, "user device resolution failed; access policy degraded open: "+err.Error())
		return UserAccessResult{Decision: UserAccessAllow}
	}
	if resolution.Untracked {
		if mode == constant.UserDevicePolicyAllowlist {
			return UserAccessResult{Decision: UserAccessDenyDevice, Reason: "device_untracked"}
		}
		return UserAccessResult{Decision: UserAccessAllow}
	}

	blocked := resolution.DeviceStatus == string(constant.UserDeviceBlocked) ||
		resolution.FingerprintStatus == string(constant.DeviceFingerprintBlocked)
	if mode == constant.UserDevicePolicyBlacklist && blocked {
		return userDeviceDeniedResult(userAccessBackendForAccess, user, resolution, evidence, now, "device_blocked")
	}
	if mode == constant.UserDevicePolicyAllowlist {
		trusted := resolution.DeviceStatus == string(constant.UserDeviceAllowed) &&
			resolution.FingerprintStatus == string(constant.DeviceFingerprintTrusted)
		grace := resolution.DeviceStatus == string(constant.UserDeviceAllowed) &&
			resolution.FingerprintStatus == string(constant.DeviceFingerprintGrace) &&
			resolution.GraceUntil > now.Unix()
		if !trusted && !grace {
			reason := "device_not_allowed"
			if resolution.FingerprintStatus == string(constant.DeviceFingerprintGrace) {
				reason = "device_grace_expired"
			}
			return userDeviceDeniedResult(userAccessBackendForAccess, user, resolution, evidence, now, reason)
		}
	}

	conflict, release := userAccessBackendForAccess.begin(
		user.Id, resolution.DeviceId, ipHash, now, mode == constant.UserDevicePolicyAllowlist,
	)
	if conflict && mode == constant.UserDevicePolicyAllowlist {
		if resolution.FingerprintStatus == string(constant.DeviceFingerprintGrace) {
			if err := userAccessBackendForAccess.markFingerprintPending(user.Id, resolution.DeviceId, resolution.FingerprintId); err != nil {
				return UserAccessResult{Decision: UserAccessUnavailable, Reason: "device_policy_unavailable"}
			}
		}
		requestCount := int64(1)
		if resolution.InitialObservationCounted {
			requestCount = 0
		}
		userAccessBackendForAccess.record(model.UserDeviceStatsUpdate{
			UserId: user.Id, DeviceId: resolution.DeviceId, FingerprintId: resolution.FingerprintId,
			RequestCount: requestCount, DeniedCount: 1, LastSeenAt: now.Unix(), ClientVersion: evidence.ClientVersion,
		})
		return UserAccessResult{
			Decision: UserAccessDenyNetwork, Reason: "device_network_conflict",
			DeviceId: resolution.DeviceId, FingerprintId: resolution.FingerprintId,
			RateLimitRPM: resolution.RateLimitRPM, BlockedModels: resolution.BlockedModels,
		}
	}

	if !resolution.InitialObservationCounted {
		userAccessBackendForAccess.record(model.UserDeviceStatsUpdate{
			UserId: user.Id, DeviceId: resolution.DeviceId, FingerprintId: resolution.FingerprintId,
			RequestCount: 1, LastSeenAt: now.Unix(), ClientVersion: evidence.ClientVersion,
			IPHash: ipHash, IP: canonicalIP,
		})
	}
	return UserAccessResult{
		Decision: UserAccessAllow, DeviceId: resolution.DeviceId,
		FingerprintId: resolution.FingerprintId, RateLimitRPM: resolution.RateLimitRPM,
		BlockedModels: resolution.BlockedModels, Release: release,
	}
}
