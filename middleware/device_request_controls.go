package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
)

const (
	userDeviceRateLimitWindowSeconds = int64(60)
	userDeviceRateLimitFallbackMax   = 10_000
	userDeviceRateLimitWarningPeriod = time.Minute
)

type userDeviceRateLimitFallbackWindow struct {
	count     int
	expiresAt int64
}

var (
	userDeviceRateLimitFallbackMu sync.Mutex
	userDeviceRateLimitFallback   = make(map[string]userDeviceRateLimitFallbackWindow)
	userDeviceRateLimitWarningMu  sync.Mutex
	userDeviceRateLimitLastWarn   time.Time
	recordUserDeviceAccessStat    = service.RecordDeviceAccessStat
)

func userDeviceRequestControls(c *gin.Context) (service.UserDeviceRequestControls, bool) {
	return common.GetContextKeyType[service.UserDeviceRequestControls](c, constant.ContextKeyUserDeviceControls)
}

func recordUserDeviceRequestDenied(c *gin.Context, controls service.UserDeviceRequestControls) {
	recordUserDeviceAccessStat(model.UserDeviceStatsUpdate{
		UserId: common.GetContextKeyInt(c, constant.ContextKeyUserId), DeviceId: controls.DeviceId,
		FingerprintId: controls.FingerprintId, DeniedCount: 1, LastSeenAt: time.Now().Unix(),
	})
}

func enforceUserDeviceModelAccess(c *gin.Context, modelName string) bool {
	controls, found := userDeviceRequestControls(c)
	if !found || !service.UserDeviceBlocksModel(controls, modelName) {
		return true
	}
	recordUserDeviceRequestDenied(c, controls)
	abortWithOpenAiMessage(
		c,
		http.StatusForbidden,
		i18n.T(c, i18n.MsgUserAccessModelNotAllowed, map[string]any{"Model": modelName}),
		types.ErrorCodeAccessDenied,
	)
	return false
}

func EnforceTokenModelAccess(c *gin.Context, modelName string) bool {
	if !common.GetContextKeyBool(c, constant.ContextKeyTokenModelLimitEnabled) {
		return true
	}
	value, found := common.GetContextKey(c, constant.ContextKeyTokenModelLimit)
	if !found {
		if controls, hasControls := userDeviceRequestControls(c); hasControls {
			recordUserDeviceRequestDenied(c, controls)
		}
		abortWithOpenAiMessage(c, http.StatusForbidden, i18n.T(c, i18n.MsgDistributorTokenNoModelAccess))
		return false
	}
	tokenModelLimit, ok := value.(map[string]bool)
	if !ok {
		tokenModelLimit = map[string]bool{}
	}
	matchName := ratio_setting.FormatMatchingModelName(modelName)
	if _, allowed := tokenModelLimit[matchName]; allowed {
		return true
	}
	if controls, hasControls := userDeviceRequestControls(c); hasControls {
		recordUserDeviceRequestDenied(c, controls)
	}
	abortWithOpenAiMessage(
		c,
		http.StatusForbidden,
		i18n.T(c, i18n.MsgDistributorTokenModelForbidden, map[string]any{"Model": modelName}),
	)
	return false
}

func userDeviceRateLimitKey(userID, deviceID int) string {
	return fmt.Sprintf("%s:device:requests:%d:%d", redisRateLimitNamespace, userID, deviceID)
}

func warnUserDeviceRateLimitFallback(c *gin.Context, now time.Time) {
	userDeviceRateLimitWarningMu.Lock()
	if !userDeviceRateLimitLastWarn.IsZero() && now.Sub(userDeviceRateLimitLastWarn) < userDeviceRateLimitWarningPeriod {
		userDeviceRateLimitWarningMu.Unlock()
		return
	}
	userDeviceRateLimitLastWarn = now
	userDeviceRateLimitWarningMu.Unlock()
	logger.LogWarn(c, "device request rate limiter Redis unavailable; using per-process fallback")
}

func takeUserDeviceRateLimitFallback(key string, maximum int, now time.Time) (bool, int64) {
	nowUnix := now.Unix()
	userDeviceRateLimitFallbackMu.Lock()
	defer userDeviceRateLimitFallbackMu.Unlock()
	var earliestExpiry int64
	if len(userDeviceRateLimitFallback) >= userDeviceRateLimitFallbackMax {
		for existingKey, window := range userDeviceRateLimitFallback {
			if window.expiresAt <= nowUnix {
				delete(userDeviceRateLimitFallback, existingKey)
			} else if earliestExpiry == 0 || window.expiresAt < earliestExpiry {
				earliestExpiry = window.expiresAt
			}
		}
	}
	window, found := userDeviceRateLimitFallback[key]
	if found && window.expiresAt <= nowUnix {
		delete(userDeviceRateLimitFallback, key)
		found = false
	}
	if !found && len(userDeviceRateLimitFallback) >= userDeviceRateLimitFallbackMax {
		retryAfter := earliestExpiry - nowUnix
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}
	if !found {
		window = userDeviceRateLimitFallbackWindow{expiresAt: nowUnix + userDeviceRateLimitWindowSeconds}
	}
	window.count++
	userDeviceRateLimitFallback[key] = window

	retryAfter := window.expiresAt - nowUnix
	if retryAfter < 1 {
		retryAfter = 1
	}
	return window.count <= maximum, retryAfter
}

func takeUserDeviceRateLimit(c *gin.Context, userID int, controls service.UserDeviceRequestControls) (bool, int64) {
	key := userDeviceRateLimitKey(userID, controls.DeviceId)
	if common.RedisEnabled && common.RDB != nil {
		allowed, _, retryAfter, err := redisFixedWindowTake(
			c.Request.Context(), key, controls.RateLimitRPM, userDeviceRateLimitWindowSeconds,
		)
		if err == nil {
			return allowed, retryAfter
		}
		warnUserDeviceRateLimitFallback(c, time.Now())
	} else if common.RedisEnabled {
		warnUserDeviceRateLimitFallback(c, time.Now())
	}
	return takeUserDeviceRateLimitFallback(key, controls.RateLimitRPM, time.Now())
}

func enforceUserDeviceRateLimit(c *gin.Context, countRequest bool) bool {
	controls, found := userDeviceRequestControls(c)
	if !found || !countRequest || controls.RateLimitRPM == 0 {
		return true
	}
	userID := common.GetContextKeyInt(c, constant.ContextKeyUserId)
	if userID <= 0 || controls.DeviceId <= 0 || controls.RateLimitRPM < 0 {
		abortUserAccessUnavailable(c)
		return false
	}
	allowed, retryAfter := takeUserDeviceRateLimit(c, userID, controls)
	if allowed {
		return true
	}
	recordUserDeviceRequestDenied(c, controls)
	if retryAfter > 0 {
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
	abortWithOpenAiMessage(
		c,
		http.StatusTooManyRequests,
		i18n.T(c, i18n.MsgUserAccessDeviceRateLimited),
		types.ErrorCodeRateLimitExceeded,
	)
	return false
}
