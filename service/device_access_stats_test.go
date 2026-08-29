package service

import (
	"errors"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetDeviceAccessStatsForTest(t *testing.T) {
	t.Helper()
	ShutdownDeviceAccessStats()
	resetDeviceAccessStatsState()
	oldApply := deviceAccessStatsApply
	deviceAccessStatsApply = model.ApplyUserDeviceStats
	t.Cleanup(func() {
		ShutdownDeviceAccessStats()
		deviceAccessStatsApply = oldApply
		resetDeviceAccessStatsState()
	})
}

func TestDeviceAccessStatsAggregatesOneHundredRecordsIntoOneBatch(t *testing.T) {
	resetDeviceAccessStatsForTest(t)
	var batches [][]model.UserDeviceStatsUpdate
	deviceAccessStatsApply = func(updates []model.UserDeviceStatsUpdate) error {
		batches = append(batches, append([]model.UserDeviceStatsUpdate(nil), updates...))
		return nil
	}

	for i := 0; i < 100; i++ {
		RecordDeviceAccessStat(model.UserDeviceStatsUpdate{
			UserId: 1, DeviceId: 2, FingerprintId: 3, RequestCount: 1,
			LastSeenAt: 100 + int64(i), IPHash: "ip-a", IP: "192.0.2.1",
			ClientVersion: "0.1.0",
		})
	}

	require.NoError(t, FlushDeviceAccessStatsAt(time.Unix(200, 0)))
	require.Len(t, batches, 1)
	require.Len(t, batches[0], 1)
	assert.EqualValues(t, 100, batches[0][0].RequestCount)
	assert.EqualValues(t, 199, batches[0][0].LastSeenAt)
}

func TestDeviceAccessStatsFlushFailureRequeuesTheSwappedMap(t *testing.T) {
	resetDeviceAccessStatsForTest(t)
	var calls int
	deviceAccessStatsApply = func(updates []model.UserDeviceStatsUpdate) error {
		calls++
		if calls == 1 {
			return errors.New("database unavailable")
		}
		assert.Len(t, updates, 1)
		assert.EqualValues(t, 2, updates[0].RequestCount)
		return nil
	}

	RecordDeviceAccessStat(model.UserDeviceStatsUpdate{UserId: 2, DeviceId: 3, RequestCount: 1, LastSeenAt: 100})
	require.Error(t, FlushDeviceAccessStatsAt(time.Unix(100, 0)))
	RecordDeviceAccessStat(model.UserDeviceStatsUpdate{UserId: 2, DeviceId: 3, RequestCount: 1, LastSeenAt: 101})
	require.NoError(t, FlushDeviceAccessStatsAt(time.Unix(101, 0)))
	assert.Equal(t, 2, calls)
}

func TestDeviceAccessStatsDoesNotPersistDeniedIPObservation(t *testing.T) {
	resetDeviceAccessStatsForTest(t)
	var persisted []model.UserDeviceStatsUpdate
	deviceAccessStatsApply = func(updates []model.UserDeviceStatsUpdate) error {
		persisted = append(persisted, updates...)
		return nil
	}

	RecordDeviceAccessStat(model.UserDeviceStatsUpdate{
		UserId: 2, DeviceId: 3, RequestCount: 1, DeniedCount: 1,
		IPHash: "denied-ip-hash", IP: "198.51.100.20", LastSeenAt: 100,
	})
	require.NoError(t, FlushDeviceAccessStatsAt(time.Unix(100, 0)))
	require.Len(t, persisted, 1)
	assert.Empty(t, persisted[0].IPHash)
	assert.Empty(t, persisted[0].IP)
}

func TestShutdownDeviceAccessStatsWaitsForFlushAndFlushesPendingRecords(t *testing.T) {
	resetDeviceAccessStatsForTest(t)
	var batches int
	deviceAccessStatsApply = func(updates []model.UserDeviceStatsUpdate) error {
		batches++
		assert.Len(t, updates, 1)
		return nil
	}

	StartDeviceAccessStats()
	RecordDeviceAccessStat(model.UserDeviceStatsUpdate{UserId: 3, DeviceId: 4, RequestCount: 1, LastSeenAt: 100})
	ShutdownDeviceAccessStats()
	assert.Equal(t, 1, batches)
}
