package service

import (
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const deviceAccessStatsInterval = time.Minute

type deviceAccessStatsKey struct {
	userID        int
	deviceID      int
	fingerprintID int
	ipHash        string
}

var (
	deviceAccessStatsMu    sync.Mutex
	deviceAccessStats      = make(map[deviceAccessStatsKey]model.UserDeviceStatsUpdate)
	deviceAccessStatsApply = model.ApplyUserDeviceStats

	deviceAccessStatsFlushMu     sync.Mutex
	deviceAccessStatsLifecycleMu sync.Mutex
	deviceAccessStatsStop        chan struct{}
	deviceAccessStatsWG          sync.WaitGroup
)

func resetDeviceAccessStatsState() {
	deviceAccessStatsMu.Lock()
	deviceAccessStats = make(map[deviceAccessStatsKey]model.UserDeviceStatsUpdate)
	deviceAccessStatsMu.Unlock()
}

func mergeDeviceAccessStats(dst *model.UserDeviceStatsUpdate, src model.UserDeviceStatsUpdate) {
	dst.RequestCount += src.RequestCount
	dst.DeniedCount += src.DeniedCount
	if src.LastSeenAt > dst.LastSeenAt {
		dst.LastSeenAt = src.LastSeenAt
		if src.ClientVersion != "" {
			dst.ClientVersion = src.ClientVersion
		}
		if src.IP != "" {
			dst.IP = src.IP
		}
	} else if dst.ClientVersion == "" && src.ClientVersion != "" {
		dst.ClientVersion = src.ClientVersion
	} else if dst.IP == "" && src.IP != "" {
		dst.IP = src.IP
	}
}

// RecordDeviceAccessStat adds one already-classified observation to the
// process-local aggregate. Stable request paths only touch this map; the
// database is updated by the periodic or explicit flush.
func RecordDeviceAccessStat(update model.UserDeviceStatsUpdate) {
	if update.UserId <= 0 || update.DeviceId <= 0 || update.RequestCount < 0 || update.DeniedCount < 0 {
		return
	}
	// A denied request must not create or refresh a recent-IP row. Callers
	// may still provide the observed IP for in-memory audit context, but only
	// successful requests are eligible for model.ApplyUserDeviceStats.
	if update.DeniedCount > 0 {
		update.IPHash = ""
		update.IP = ""
	}
	key := deviceAccessStatsKey{
		userID: update.UserId, deviceID: update.DeviceId,
		fingerprintID: update.FingerprintId, ipHash: update.IPHash,
	}
	deviceAccessStatsMu.Lock()
	current, ok := deviceAccessStats[key]
	if !ok {
		current = update
	} else {
		mergeDeviceAccessStats(&current, update)
	}
	deviceAccessStats[key] = current
	deviceAccessStatsMu.Unlock()
}

func swapDeviceAccessStats() []model.UserDeviceStatsUpdate {
	deviceAccessStatsMu.Lock()
	if len(deviceAccessStats) == 0 {
		deviceAccessStatsMu.Unlock()
		return nil
	}
	updates := make([]model.UserDeviceStatsUpdate, 0, len(deviceAccessStats))
	for _, update := range deviceAccessStats {
		updates = append(updates, update)
	}
	deviceAccessStats = make(map[deviceAccessStatsKey]model.UserDeviceStatsUpdate)
	deviceAccessStatsMu.Unlock()
	return updates
}

func requeueDeviceAccessStats(updates []model.UserDeviceStatsUpdate) {
	deviceAccessStatsMu.Lock()
	defer deviceAccessStatsMu.Unlock()
	for _, update := range updates {
		key := deviceAccessStatsKey{
			userID: update.UserId, deviceID: update.DeviceId,
			fingerprintID: update.FingerprintId, ipHash: update.IPHash,
		}
		current, ok := deviceAccessStats[key]
		if !ok {
			deviceAccessStats[key] = update
			continue
		}
		mergeDeviceAccessStats(&current, update)
		deviceAccessStats[key] = current
	}
}

// FlushDeviceAccessStatsAt swaps the current aggregate and applies it as one
// database batch. A failed batch is merged back so no observations vanish.
func FlushDeviceAccessStatsAt(_ time.Time) error {
	deviceAccessStatsFlushMu.Lock()
	defer deviceAccessStatsFlushMu.Unlock()
	updates := swapDeviceAccessStats()
	if len(updates) == 0 {
		return nil
	}
	if err := deviceAccessStatsApply(updates); err != nil {
		requeueDeviceAccessStats(updates)
		common.SysError("failed to flush device access statistics: " + err.Error())
		return err
	}
	return nil
}

// FlushDeviceAccessStats flushes the aggregate using the current wall clock.
func FlushDeviceAccessStats() error {
	return FlushDeviceAccessStatsAt(time.Now())
}

func deviceAccessStatsLoop(stop <-chan struct{}) {
	defer deviceAccessStatsWG.Done()
	ticker := time.NewTicker(deviceAccessStatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = FlushDeviceAccessStats()
		case <-stop:
			return
		}
	}
}

// StartDeviceAccessStats starts the per-node one-minute aggregate flusher.
// Repeated starts are harmless.
func StartDeviceAccessStats() {
	deviceAccessStatsLifecycleMu.Lock()
	defer deviceAccessStatsLifecycleMu.Unlock()
	if deviceAccessStatsStop != nil {
		return
	}
	deviceAccessStatsStop = make(chan struct{})
	deviceAccessStatsWG.Add(1)
	go deviceAccessStatsLoop(deviceAccessStatsStop)
}

// ShutdownDeviceAccessStats stops the ticker, waits for any in-progress
// periodic flush to finish, then performs the final shutdown flush.
func ShutdownDeviceAccessStats() error {
	deviceAccessStatsLifecycleMu.Lock()
	stop := deviceAccessStatsStop
	deviceAccessStatsStop = nil
	deviceAccessStatsLifecycleMu.Unlock()
	if stop != nil {
		close(stop)
		deviceAccessStatsWG.Wait()
	}
	return FlushDeviceAccessStats()
}
