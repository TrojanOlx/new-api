package middleware

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
)

const userDeviceActivityContextKey = "user_device_activity"

var (
	userDeviceActivityLeaseInterval    = service.DeviceActivityLeaseInterval
	touchUserDeviceNetworkActivity     = service.TouchDeviceNetworkActivity
	evaluateUserAPIAccessForMiddleware = service.EvaluateUserAPIAccess
)

type userDeviceActivity struct {
	userID   int
	deviceID int
	ipHash   string
	release  func()
}

func enforceTokenIPAccess(c *gin.Context, token *model.Token) bool {
	allowIPs := token.GetIpLimits()
	if len(allowIPs) == 0 {
		return true
	}
	clientIP := c.ClientIP()
	logger.LogDebug(c, "Token has IP restrictions, checking client IP %s", clientIP)
	ip := net.ParseIP(clientIP)
	if ip == nil || !common.IsIpInCIDRList(ip, allowIPs) {
		abortWithOpenAiMessage(c, 403, common.TranslateMessage(c, i18n.MsgUserAccessIPNotAllowed), types.ErrorCodeAccessDenied)
		return false
	}
	logger.LogDebug(c, "Client IP %s passed the token IP restrictions check", clientIP)
	return true
}

func abortUserAccessUnavailable(c *gin.Context) {
	c.Header("Retry-After", "3")
	abortWithOpenAiMessage(c, 503, common.TranslateMessage(c, i18n.MsgUserAccessUnavailable), types.ErrorCodeAccessControlUnavailable)
}

func enforceUserAPIAccess(c *gin.Context, user *model.UserBase) bool {
	clientIP, err := netip.ParseAddr(c.ClientIP())
	if err != nil {
		abortWithOpenAiMessage(c, 403, common.TranslateMessage(c, i18n.MsgUserAccessIPNotAllowed), types.ErrorCodeAccessDenied)
		return false
	}

	metadata := service.DeviceRequestMetadata{
		UserAgent:         c.GetHeader("User-Agent"),
		Originator:        c.GetHeader("Originator"),
		CodexInstallation: c.GetHeader("X-Codex-Installation-Id"),
		CodexWindow:       c.GetHeader("X-Codex-Window-Id"),
		StainlessOS:       c.GetHeader("X-Stainless-OS"),
		StainlessArch:     c.GetHeader("X-Stainless-Arch"),
		StainlessRuntime:  c.GetHeader("X-Stainless-Runtime"),
		StainlessVersion:  c.GetHeader("X-Stainless-Package-Version"),
		App:               c.GetHeader("X-Stainless-App"),
	}
	if IsTrustedProxyRemoteAddr(c.Request.RemoteAddr) {
		metadata.EdgeJA4 = c.GetHeader("X-New-Api-Edge-JA4")
		metadata.EdgeHTTP2 = c.GetHeader("X-New-Api-Edge-H2")
	}

	result := evaluateUserAPIAccessForMiddleware(user, clientIP, metadata, time.Now())
	switch result.Decision {
	case service.UserAccessAllow:
		if result.DeviceId > 0 {
			c.Set(string(constant.ContextKeyUserDeviceControls), service.UserDeviceRequestControls{
				DeviceId: result.DeviceId, FingerprintId: result.FingerprintId,
				RateLimitRPM:  result.RateLimitRPM,
				BlockedModels: append([]string(nil), result.BlockedModels...),
			})
		}
		if result.Release != nil {
			canonicalIP := clientIP.Unmap().String()
			var releaseOnce sync.Once
			c.Set(userDeviceActivityContextKey, userDeviceActivity{
				userID: user.Id, deviceID: result.DeviceId,
				ipHash:  common.GenerateHMACWithKey([]byte("device-ip-v1:"+common.DeviceFingerprintSecret), canonicalIP),
				release: func() { releaseOnce.Do(result.Release) },
			})
		}
		return true
	case service.UserAccessDenyIP:
		abortWithOpenAiMessage(c, 403, common.TranslateMessage(c, i18n.MsgUserAccessIPNotAllowed), types.ErrorCodeAccessDenied)
	case service.UserAccessDenyNetwork:
		abortWithOpenAiMessage(c, 403, common.TranslateMessage(c, i18n.MsgUserAccessNetworkConflict), types.ErrorCodeAccessDenied)
	case service.UserAccessDenyDevice:
		messageKey := i18n.MsgUserAccessDeviceNotAllowed
		switch result.Reason {
		case "device_blocked":
			messageKey = i18n.MsgUserAccessDeviceBlocked
		case "device_grace_expired":
			messageKey = i18n.MsgUserAccessUpgradeGraceExpired
		}
		abortWithOpenAiMessage(c, 403, common.TranslateMessage(c, messageKey), types.ErrorCodeAccessDenied)
	default:
		abortUserAccessUnavailable(c)
	}
	return false
}

func releaseUserDeviceActivity(c *gin.Context) {
	value, ok := c.Get(userDeviceActivityContextKey)
	if !ok {
		return
	}
	activity, ok := value.(userDeviceActivity)
	if ok && activity.release != nil {
		activity.release()
	}
}

func continueUserAPIAccess(c *gin.Context) {
	value, ok := c.Get(userDeviceActivityContextKey)
	if !ok {
		c.Next()
		return
	}
	activity, ok := value.(userDeviceActivity)
	if !ok {
		c.Next()
		return
	}
	continueWithUserDeviceActivity(c, activity)
}

func continueWithUserDeviceActivity(c *gin.Context, activity userDeviceActivity) {
	if activity.release == nil {
		c.Next()
		return
	}

	done := make(chan struct{})
	var renewals sync.WaitGroup
	if activity.userID > 0 && activity.deviceID > 0 && activity.ipHash != "" && userDeviceActivityLeaseInterval > 0 {
		renewals.Add(1)
		go func() {
			defer renewals.Done()
			ticker := time.NewTicker(userDeviceActivityLeaseInterval)
			defer ticker.Stop()
			for {
				select {
				case now := <-ticker.C:
					touchUserDeviceNetworkActivity(activity.userID, activity.deviceID, activity.ipHash, now)
				case <-done:
					return
				}
			}
		}()
	}
	defer activity.release()
	defer func() {
		close(done)
		renewals.Wait()
	}()
	c.Next()
}
