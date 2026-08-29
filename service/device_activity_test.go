package service

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetDeviceActivityForTest(t *testing.T) {
	t.Helper()
	resetDeviceActivityState()
	oldEnabled, oldRDB := common.RedisEnabled, common.RDB
	common.RedisEnabled = false
	common.RDB = nil
	t.Cleanup(func() {
		resetDeviceActivityState()
		common.RedisEnabled, common.RDB = oldEnabled, oldRDB
	})
}

func useDeviceActivityRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	server, err := miniredis.Run()
	require.NoError(t, err)
	oldEnabled, oldRDB := common.RedisEnabled, common.RDB
	common.RedisEnabled = true
	common.RDB = redis.NewClient(&redis.Options{Addr: server.Addr()})
	resetDeviceActivityState()
	t.Cleanup(func() {
		resetDeviceActivityState()
		_ = common.RDB.Close()
		common.RedisEnabled, common.RDB = oldEnabled, oldRDB
		server.Close()
	})
	return server
}

func TestDeviceActivitySameIPConcurrentRequestsShareOneNetwork(t *testing.T) {
	resetDeviceActivityForTest(t)
	now := time.Unix(1_000_000, 0)
	deviceActivityNowFunc = func() time.Time { return now }

	conflictOne, releaseOne := BeginDeviceNetworkActivity(7, 11, "ip-a", now, true)
	conflictTwo, releaseTwo := BeginDeviceNetworkActivity(7, 11, "ip-a", now, true)
	assert.False(t, conflictOne)
	assert.False(t, conflictTwo)

	releaseOne()
	releaseOne()
	conflictOther, releaseOther := BeginDeviceNetworkActivity(7, 11, "ip-b", now.Add(time.Second), true)
	assert.True(t, conflictOther)
	assert.Nil(t, releaseOther)

	releaseTwo()
	conflictOther, releaseOther = BeginDeviceNetworkActivity(7, 11, "ip-b", now.Add(time.Second), true)
	assert.True(t, conflictOther, "a different IP remains recent after release")
	assert.Nil(t, releaseOther)

	conflictSame, releaseSame := BeginDeviceNetworkActivity(7, 11, "ip-a", now.Add(16*time.Minute), true)
	assert.False(t, conflictSame)
	releaseSame()
}

func TestDeviceActivityDifferentIPConflictsUntilRecentWindowExpires(t *testing.T) {
	resetDeviceActivityForTest(t)
	now := time.Unix(2_000_000, 0)
	deviceActivityNowFunc = func() time.Time { return now }

	conflict, release := BeginDeviceNetworkActivity(8, 12, "ip-a", now, true)
	assert.False(t, conflict)
	conflict, deniedRelease := BeginDeviceNetworkActivity(8, 12, "ip-b", now.Add(time.Second), true)
	assert.True(t, conflict)
	assert.Nil(t, deniedRelease)
	release()

	assert.True(t, HasDeviceNetworkConflict(8, 12, "ip-b", now.Add(time.Second)))
	assert.False(t, HasDeviceNetworkConflict(8, 12, "ip-a", now.Add(time.Second)))

	conflict, release = BeginDeviceNetworkActivity(8, 12, "ip-b", now.Add(15*time.Minute), true)
	assert.False(t, conflict, "the recent window expires at its boundary")
	release()
}

func TestDeviceActivityReleaseIsIdempotentAndTouchRenewsLease(t *testing.T) {
	server := useDeviceActivityRedis(t)
	now := time.Unix(3_000_000, 0)
	deviceActivityNowFunc = func() time.Time { return now }

	conflict, release := BeginDeviceNetworkActivity(9, 13, "ip-a", now, true)
	require.False(t, conflict)
	require.True(t, TouchDeviceNetworkActivity(9, 13, "ip-a", now.Add(5*time.Minute)))
	release()
	release()

	assert.True(t, server.Exists(deviceActivityRecentKey(9, 13)))
	assert.True(t, HasDeviceNetworkConflict(9, 13, "ip-b", now.Add(6*time.Minute)))
}

func TestDeviceActivityObserveConflictIsRegisteredInRedis(t *testing.T) {
	server := useDeviceActivityRedis(t)
	now := time.Unix(3_500_000, 0)
	deviceActivityNowFunc = func() time.Time { return now }

	conflict, releaseA := BeginDeviceNetworkActivity(9, 13, "ip-a", now, true)
	require.False(t, conflict)
	conflict, releaseB := BeginDeviceNetworkActivity(9, 13, "ip-b", now.Add(time.Second), false)
	require.True(t, conflict)
	require.NotNil(t, releaseB)
	releaseA()
	releaseB()

	// Both IPs were observed, so returning to the original network remains in
	// conflict even after the original active request has ended.
	conflict, releaseC := BeginDeviceNetworkActivity(9, 13, "ip-a", now.Add(2*time.Second), true)
	assert.True(t, conflict)
	assert.Nil(t, releaseC)
	assert.True(t, server.Exists(deviceActivityRecentKey(9, 13)))
}

func TestDeviceActivityRedisCleansExpiredActiveLeaseWhenKeyIsStillAlive(t *testing.T) {
	server := useDeviceActivityRedis(t)
	now := time.Unix(3_600_000, 0)
	deviceActivityNowFunc = func() time.Time { return now }

	conflict, releaseA := BeginDeviceNetworkActivity(9, 13, "ip-a", now, true)
	require.False(t, conflict)
	conflict, releaseB := BeginDeviceNetworkActivity(9, 13, "ip-b", now.Add(time.Second), false)
	require.True(t, conflict)
	require.NotNil(t, releaseB)

	// The active key remains present because the second request refreshed its
	// TTL, but both leases are older than the 30-minute crash cleanup window.
	conflict, releaseC := BeginDeviceNetworkActivity(9, 13, "ip-c", now.Add(31*time.Minute), true)
	assert.False(t, conflict)
	assert.True(t, server.Exists(deviceActivityActiveKey(9, 13)))
	if releaseC != nil {
		releaseC()
	}
	releaseA()
	releaseB()
}

func TestDeviceActivityRedisFailureFallsBackToInProcessState(t *testing.T) {
	server := useDeviceActivityRedis(t)
	now := time.Unix(4_000_000, 0)
	deviceActivityNowFunc = func() time.Time { return now }
	server.Close()

	conflict, release := BeginDeviceNetworkActivity(10, 14, "ip-a", now, true)
	assert.False(t, conflict)
	conflict, deniedRelease := BeginDeviceNetworkActivity(10, 14, "ip-b", now.Add(time.Second), true)
	assert.True(t, conflict)
	release()
	assert.Nil(t, deniedRelease)
}
