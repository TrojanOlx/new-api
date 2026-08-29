package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/go-redis/redis/v8"
)

const (
	// DeviceActivityRecentWindow is the period in which a different IP is
	// considered to be part of the same recent network activity window.
	DeviceActivityRecentWindow = 15 * time.Minute
	// DeviceActivityKeyTTL bounds the lifetime of an idle activity record.
	DeviceActivityKeyTTL = 30 * time.Minute
	// DeviceActivityLeaseInterval is the interval callers should use for
	// renewing long-lived requests before the activity key expires.
	DeviceActivityLeaseInterval = 5 * time.Minute
)

const (
	deviceActivityRecentKeySuffix = ":recent"
	deviceActivityActiveKeySuffix = ":active"
	deviceActivityWarningInterval = time.Minute
)

var deviceActivityBeginScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local cutoff = now - tonumber(ARGV[3])
local leaseCutoff = now - tonumber(ARGV[4])
local ip = ARGV[2]
local reject = tonumber(ARGV[5]) == 1

local active = redis.call('HGETALL', KEYS[2])
for i = 1, #active, 2 do
  local count, lease = string.match(active[i + 1], '^(%d+):(%-?%d+)$')
  if count == nil then
    count = tonumber(active[i + 1])
    lease = now
  else
    count = tonumber(count)
    lease = tonumber(lease)
  end
  if lease <= leaseCutoff then
    redis.call('HDEL', KEYS[2], active[i])
  else
    redis.call('HSET', KEYS[2], active[i], count .. ':' .. lease)
  end
end

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)

local recent = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
for i = 1, #recent, 2 do
  if recent[i] ~= ip and tonumber(recent[i + 1]) > cutoff then
    redis.call('EXPIRE', KEYS[1], ARGV[4])
    redis.call('EXPIRE', KEYS[2], ARGV[4])
    if reject then
      return 0
    end
    local count, lease = string.match(redis.call('HGET', KEYS[2], ip) or '0', '^(%d+):(%-?%d+)$')
    if count == nil then
      count = tonumber(redis.call('HGET', KEYS[2], ip) or '0')
    else
      count = tonumber(count)
    end
    redis.call('HSET', KEYS[2], ip, (count + 1) .. ':' .. now)
    return 2
  end
end

active = redis.call('HGETALL', KEYS[2])
for i = 1, #active, 2 do
  local count, lease = string.match(active[i + 1], '^(%d+):(%-?%d+)$')
  if count == nil then
    count = tonumber(active[i + 1])
    lease = now
  else
    count = tonumber(count)
    lease = tonumber(lease)
  end
  if active[i] ~= ip and count > 0 and lease > leaseCutoff then
    redis.call('EXPIRE', KEYS[1], ARGV[4])
    redis.call('EXPIRE', KEYS[2], ARGV[4])
    if reject then
      return 0
    end
    local currentCount = string.match(redis.call('HGET', KEYS[2], ip) or '0', '^(%d+):')
    if currentCount == nil then
      currentCount = tonumber(redis.call('HGET', KEYS[2], ip) or '0')
    else
      currentCount = tonumber(currentCount)
    end
    redis.call('HSET', KEYS[2], ip, (currentCount + 1) .. ':' .. now)
    return 2
  end
end

local count = string.match(redis.call('HGET', KEYS[2], ip) or '0', '^(%d+):')
if count == nil then
  count = tonumber(redis.call('HGET', KEYS[2], ip) or '0')
else
  count = tonumber(count)
end
redis.call('HSET', KEYS[2], ip, (count + 1) .. ':' .. now)
redis.call('EXPIRE', KEYS[1], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[4])
return 1
`)

var deviceActivityReleaseScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local ip = ARGV[2]
local value = redis.call('HGET', KEYS[2], ip) or '0'
local count, lease = string.match(value, '^(%d+):(%-?%d+)$')
if count == nil then
  count = tonumber(value)
else
  count = tonumber(count)
  lease = tonumber(lease)
end
if count <= 0 then
  return 0
end

if count == 1 then
  redis.call('HDEL', KEYS[2], ip)
  redis.call('ZADD', KEYS[1], now, ip)
else
  redis.call('HSET', KEYS[2], ip, (count - 1) .. ':' .. (lease or now))
end
redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('EXPIRE', KEYS[2], ARGV[3])
return 1
`)

var deviceActivityTouchScript = redis.NewScript(`
local ip = ARGV[1]
local value = redis.call('HGET', KEYS[2], ip)
if value == false then
  return 0
end
local count = string.match(value, '^(%d+):')
if count == nil then
  count = tonumber(value)
else
  count = tonumber(count)
end
if count <= 0 then
  return 0
end
redis.call('HSET', KEYS[2], ip, count .. ':' .. ARGV[3])
redis.call('EXPIRE', KEYS[1], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[2])
return 1
`)

var deviceActivityConflictScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local cutoff = now - tonumber(ARGV[3])
local leaseCutoff = now - tonumber(ARGV[4])
local ip = ARGV[2]

local recent = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
for i = 1, #recent, 2 do
  if recent[i] ~= ip and tonumber(recent[i + 1]) > cutoff then
    return 1
  end
end

local active = redis.call('HGETALL', KEYS[2])
for i = 1, #active, 2 do
  local count, lease = string.match(active[i + 1], '^(%d+):(%-?%d+)$')
  if count == nil then
    count = tonumber(active[i + 1])
    lease = now
  else
    count = tonumber(count)
    lease = tonumber(lease)
  end
  if active[i] ~= ip and count > 0 and lease > leaseCutoff then
    return 1
  end
end
return 0
`)

type deviceActivityLocalKey struct {
	userID   int
	deviceID int
}

type deviceActivityLocalState struct {
	active  map[string]int
	leaseAt map[string]int64
	recent  map[string]int64
}

var deviceActivityState = struct {
	sync.Mutex
	entries  map[deviceActivityLocalKey]*deviceActivityLocalState
	lastWarn time.Time
}{entries: make(map[deviceActivityLocalKey]*deviceActivityLocalState)}

// deviceActivityNowFunc is injectable so tests can advance release time
// without sleeping. Production uses the wall clock.
var deviceActivityNowFunc = time.Now

func deviceActivityBaseKey(userID, deviceID int) string {
	return fmt.Sprintf("device:activity:{%d}:{%d}", userID, deviceID)
}

func deviceActivityRecentKey(userID, deviceID int) string {
	return deviceActivityBaseKey(userID, deviceID) + deviceActivityRecentKeySuffix
}

func deviceActivityActiveKey(userID, deviceID int) string {
	return deviceActivityBaseKey(userID, deviceID) + deviceActivityActiveKeySuffix
}

func resetDeviceActivityState() {
	deviceActivityState.Lock()
	deviceActivityState.entries = make(map[deviceActivityLocalKey]*deviceActivityLocalState)
	deviceActivityState.lastWarn = time.Time{}
	deviceActivityState.Unlock()
	deviceActivityNowFunc = time.Now
}

func deviceActivityUnix(now time.Time) int64 {
	if now.IsZero() {
		now = deviceActivityNowFunc()
	}
	return now.Unix()
}

func deviceActivityBoolArg(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func deviceActivityCurrentUnix() int64 {
	return deviceActivityUnix(deviceActivityNowFunc())
}

func deviceActivityValid(userID, deviceID int, ipHash string) bool {
	return userID > 0 && deviceID > 0 && ipHash != ""
}

func deviceActivityWarn(now time.Time, err error) {
	if now.IsZero() {
		now = time.Now()
	}
	deviceActivityState.Lock()
	if !deviceActivityState.lastWarn.IsZero() && now.Sub(deviceActivityState.lastWarn) < deviceActivityWarningInterval {
		deviceActivityState.Unlock()
		return
	}
	deviceActivityState.lastWarn = now
	deviceActivityState.Unlock()
	if err == nil {
		common.SysError("device activity Redis unavailable; using in-process detection")
		return
	}
	common.SysError("device activity Redis unavailable; using in-process detection: " + err.Error())
}

func deviceActivityRedisAvailable() bool {
	return common.RedisEnabled && common.RDB != nil
}

func deviceActivityRedisKeys(userID, deviceID int) []string {
	return []string{deviceActivityRecentKey(userID, deviceID), deviceActivityActiveKey(userID, deviceID)}
}

func deviceActivityNoopRelease() func() {
	return nil
}

func deviceActivityBeginLocal(userID, deviceID int, ipHash string, now int64, rejectOnConflict bool) (bool, func()) {
	key := deviceActivityLocalKey{userID: userID, deviceID: deviceID}
	cutoff := now - int64(DeviceActivityRecentWindow/time.Second)
	expiry := now - int64(DeviceActivityKeyTTL/time.Second)

	deviceActivityState.Lock()
	state := deviceActivityState.entries[key]
	if state == nil {
		state = &deviceActivityLocalState{
			active:  make(map[string]int),
			leaseAt: make(map[string]int64),
			recent:  make(map[string]int64),
		}
		deviceActivityState.entries[key] = state
	}
	for ip, seenAt := range state.recent {
		if seenAt <= cutoff || seenAt <= expiry {
			delete(state.recent, ip)
		}
	}
	for ip, leaseAt := range state.leaseAt {
		if state.active[ip] > 0 && leaseAt <= expiry {
			delete(state.active, ip)
			delete(state.leaseAt, ip)
		}
	}

	conflict := false
	for ip, count := range state.active {
		if ip != ipHash && count > 0 {
			conflict = true
			break
		}
	}
	if !conflict {
		for ip, seenAt := range state.recent {
			if ip != ipHash && seenAt > cutoff {
				conflict = true
				break
			}
		}
	}
	if conflict && rejectOnConflict {
		deviceActivityState.Unlock()
		return true, deviceActivityNoopRelease()
	}
	state.active[ipHash]++
	state.leaseAt[ipHash] = now
	deviceActivityState.Unlock()

	var once sync.Once
	return conflict, func() {
		once.Do(func() { deviceActivityReleaseLocal(userID, deviceID, ipHash, deviceActivityCurrentUnix()) })
	}
}

func deviceActivityReleaseLocal(userID, deviceID int, ipHash string, now int64) {
	key := deviceActivityLocalKey{userID: userID, deviceID: deviceID}
	deviceActivityState.Lock()
	defer deviceActivityState.Unlock()
	state := deviceActivityState.entries[key]
	if state == nil || state.active[ipHash] <= 0 {
		return
	}
	if state.active[ipHash] == 1 {
		delete(state.active, ipHash)
		delete(state.leaseAt, ipHash)
		if old, ok := state.recent[ipHash]; !ok || now > old {
			state.recent[ipHash] = now
		}
	} else {
		state.active[ipHash]--
	}
}

func deviceActivityTouchLocal(userID, deviceID int, ipHash string, now int64) bool {
	key := deviceActivityLocalKey{userID: userID, deviceID: deviceID}
	deviceActivityState.Lock()
	defer deviceActivityState.Unlock()
	state := deviceActivityState.entries[key]
	if state == nil || state.active[ipHash] <= 0 {
		return false
	}
	state.leaseAt[ipHash] = now
	return true
}

func deviceActivityConflictLocal(userID, deviceID int, ipHash string, now int64) bool {
	key := deviceActivityLocalKey{userID: userID, deviceID: deviceID}
	cutoff := now - int64(DeviceActivityRecentWindow/time.Second)
	expiry := now - int64(DeviceActivityKeyTTL/time.Second)
	deviceActivityState.Lock()
	defer deviceActivityState.Unlock()
	state := deviceActivityState.entries[key]
	if state == nil {
		return false
	}
	for ip, seenAt := range state.recent {
		if seenAt <= cutoff || seenAt <= expiry {
			delete(state.recent, ip)
		}
	}
	for ip, leaseAt := range state.leaseAt {
		if state.active[ip] > 0 && leaseAt <= expiry {
			delete(state.active, ip)
			delete(state.leaseAt, ip)
		}
	}
	for ip, count := range state.active {
		if ip != ipHash && count > 0 {
			return true
		}
	}
	for ip, seenAt := range state.recent {
		if ip != ipHash && seenAt > cutoff {
			return true
		}
	}
	return false
}

func deviceActivityRecordLocalRecent(userID, deviceID int, ipHash string, now int64) {
	key := deviceActivityLocalKey{userID: userID, deviceID: deviceID}
	deviceActivityState.Lock()
	defer deviceActivityState.Unlock()
	state := deviceActivityState.entries[key]
	if state == nil {
		state = &deviceActivityLocalState{
			active:  make(map[string]int),
			leaseAt: make(map[string]int64),
			recent:  make(map[string]int64),
		}
		deviceActivityState.entries[key] = state
	}
	if old, ok := state.recent[ipHash]; !ok || now > old {
		state.recent[ipHash] = now
	}
}

// BeginDeviceNetworkActivity registers one request for a logical device. If
// another IP is active or recent, conflict is true. In reject mode a
// conflicting request is not registered, so its IP cannot pollute the recent
// network window. In observe/blacklist mode it is registered and must release
// the returned handle when the request ends.
func BeginDeviceNetworkActivity(userID, deviceID int, ipHash string, now time.Time, rejectOnConflict bool) (conflict bool, release func()) {
	if !deviceActivityValid(userID, deviceID, ipHash) {
		return true, deviceActivityNoopRelease()
	}
	nowUnix := deviceActivityUnix(now)
	if deviceActivityRedisAvailable() {
		result, err := deviceActivityBeginScript.Run(
			context.Background(), common.RDB, deviceActivityRedisKeys(userID, deviceID),
			nowUnix, ipHash, int64(DeviceActivityRecentWindow/time.Second), int64(DeviceActivityKeyTTL/time.Second), deviceActivityBoolArg(rejectOnConflict),
		).Int()
		if err == nil {
			if result == 0 {
				return true, deviceActivityNoopRelease()
			}
			conflict = result == 2
			_, localRelease := deviceActivityBeginLocal(userID, deviceID, ipHash, nowUnix, false)
			var once sync.Once
			return conflict, func() {
				once.Do(func() {
					localRelease()
					releaseNow := deviceActivityCurrentUnix()
					if err := deviceActivityReleaseRedis(userID, deviceID, ipHash, releaseNow); err != nil {
						deviceActivityWarn(now, err)
					}
				})
			}
		}
		deviceActivityWarn(now, err)
	}
	return deviceActivityBeginLocal(userID, deviceID, ipHash, nowUnix, rejectOnConflict)
}

func deviceActivityReleaseRedis(userID, deviceID int, ipHash string, nowUnix int64) error {
	if !deviceActivityRedisAvailable() {
		return fmt.Errorf("Redis is disabled")
	}
	_, err := deviceActivityReleaseScript.Run(
		context.Background(), common.RDB, deviceActivityRedisKeys(userID, deviceID),
		nowUnix, ipHash, int64(DeviceActivityKeyTTL/time.Second),
	).Int()
	return err
}

// TouchDeviceNetworkActivity renews the 30-minute activity lease. Callers
// serving long-lived streams should invoke it at the five-minute interval.
func TouchDeviceNetworkActivity(userID, deviceID int, ipHash string, now time.Time) bool {
	if !deviceActivityValid(userID, deviceID, ipHash) {
		return false
	}
	if deviceActivityRedisAvailable() {
		result, err := deviceActivityTouchScript.Run(
			context.Background(), common.RDB, deviceActivityRedisKeys(userID, deviceID),
			ipHash, int64(DeviceActivityKeyTTL/time.Second), deviceActivityUnix(now),
		).Int()
		if err == nil {
			if result == 1 {
				_ = deviceActivityTouchLocal(userID, deviceID, ipHash, deviceActivityUnix(now))
			}
			return result == 1
		}
		deviceActivityWarn(now, err)
	}
	return deviceActivityTouchLocal(userID, deviceID, ipHash, deviceActivityUnix(now))
}

// HasDeviceNetworkConflict checks whether an IP is currently incompatible
// with another active or recent IP for the same logical device. It never
// registers activity and therefore is safe to use during upgrade association.
func HasDeviceNetworkConflict(userID, deviceID int, ipHash string, now time.Time) bool {
	if !deviceActivityValid(userID, deviceID, ipHash) {
		return true
	}
	nowUnix := deviceActivityUnix(now)
	if deviceActivityRedisAvailable() {
		result, err := deviceActivityConflictScript.Run(
			context.Background(), common.RDB, deviceActivityRedisKeys(userID, deviceID),
			nowUnix, ipHash, int64(DeviceActivityRecentWindow/time.Second), int64(DeviceActivityKeyTTL/time.Second),
		).Int()
		if err == nil {
			return result == 1
		}
		deviceActivityWarn(now, err)
	}
	return deviceActivityConflictLocal(userID, deviceID, ipHash, nowUnix)
}

// IsDeviceNetworkContinuous is retained as a compatibility helper for
// callers that use the old positive naming. It returns true when no other IP
// is active or recent.
func IsDeviceNetworkContinuous(userID, deviceID int, ipHash string, now time.Time) bool {
	return !HasDeviceNetworkConflict(userID, deviceID, ipHash, now)
}
