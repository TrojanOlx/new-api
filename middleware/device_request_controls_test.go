package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	appI18n "github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deviceRequestControlErrorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

func resetUserDeviceRateLimitFallbackForTest() {
	userDeviceRateLimitFallbackMu.Lock()
	userDeviceRateLimitFallback = make(map[string]userDeviceRateLimitFallbackWindow)
	userDeviceRateLimitFallbackMu.Unlock()
}

func discardUserDeviceAccessStatsForTest(t *testing.T) {
	t.Helper()
	previous := recordUserDeviceAccessStat
	recordUserDeviceAccessStat = func(model.UserDeviceStatsUpdate) {}
	t.Cleanup(func() { recordUserDeviceAccessStat = previous })
}

func newDeviceRequestControlTestContext(t *testing.T, userID, deviceID, fingerprintID, rateLimitRPM int, blockedModels []string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	require.NoError(t, appI18n.Init())
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(string(constant.ContextKeyUserId), userID)
	c.Set(string(constant.ContextKeyUserDeviceControls), service.UserDeviceRequestControls{
		DeviceId:      deviceID,
		FingerprintId: fingerprintID,
		RateLimitRPM:  rateLimitRPM,
		BlockedModels: blockedModels,
	})
	return c, recorder
}

func decodeDeviceRequestControlError(t *testing.T, recorder *httptest.ResponseRecorder) deviceRequestControlErrorResponse {
	t.Helper()
	var response deviceRequestControlErrorResponse
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
	return response
}

func TestEnforceUserDeviceModelAccessRequiresExactModelID(t *testing.T) {
	discardUserDeviceAccessStatsForTest(t)
	for _, testCase := range []struct {
		name        string
		modelName   string
		wantAllowed bool
		wantStatus  int
	}{
		{name: "exact blocked model", modelName: "gpt-5.6-sol", wantAllowed: false, wantStatus: http.StatusForbidden},
		{name: "model alias remains allowed", modelName: "gpt-5.6", wantAllowed: true, wantStatus: http.StatusOK},
		{name: "different case remains allowed", modelName: "GPT-5.6-SOL", wantAllowed: true, wantStatus: http.StatusOK},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			c, recorder := newDeviceRequestControlTestContext(t, 41, 91, 101, 0, []string{"gpt-5.6-sol"})

			allowed := enforceUserDeviceModelAccess(c, testCase.modelName)

			assert.Equal(t, testCase.wantAllowed, allowed)
			assert.Equal(t, testCase.wantStatus, recorder.Code)
			if !testCase.wantAllowed {
				assert.Equal(t, "access_denied", decodeDeviceRequestControlError(t, recorder).Error.Code)
			}
		})
	}
}

func TestEnforceUserDeviceRateLimitSharesLogicalDeviceBucket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	discardUserDeviceAccessStatsForTest(t)
	useRateLimitMiniRedis(t)
	resetUserDeviceRateLimitFallbackForTest()
	t.Cleanup(resetUserDeviceRateLimitFallbackForTest)

	first, firstRecorder := newDeviceRequestControlTestContext(t, 42, 92, 102, 2, nil)
	second, secondRecorder := newDeviceRequestControlTestContext(t, 42, 92, 103, 2, nil)
	third, thirdRecorder := newDeviceRequestControlTestContext(t, 42, 92, 104, 2, nil)
	otherDevice, otherDeviceRecorder := newDeviceRequestControlTestContext(t, 42, 93, 105, 2, nil)

	assert.True(t, enforceUserDeviceRateLimit(first, true))
	assert.Equal(t, http.StatusOK, firstRecorder.Code)
	assert.True(t, enforceUserDeviceRateLimit(second, true))
	assert.Equal(t, http.StatusOK, secondRecorder.Code)

	assert.False(t, enforceUserDeviceRateLimit(third, true))
	assert.Equal(t, http.StatusTooManyRequests, thirdRecorder.Code)
	assert.NotEmpty(t, thirdRecorder.Header().Get("Retry-After"))
	assert.Equal(t, "rate_limit_exceeded", decodeDeviceRequestControlError(t, thirdRecorder).Error.Code)

	assert.True(t, enforceUserDeviceRateLimit(otherDevice, true))
	assert.Equal(t, http.StatusOK, otherDeviceRecorder.Code)
}

func TestEnforceUserDeviceRateLimitDoesNotConsumeWhenCountingIsDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	discardUserDeviceAccessStatsForTest(t)
	useRateLimitMiniRedis(t)
	resetUserDeviceRateLimitFallbackForTest()
	t.Cleanup(resetUserDeviceRateLimitFallbackForTest)

	probe, probeRecorder := newDeviceRequestControlTestContext(t, 43, 94, 106, 1, nil)
	counted, countedRecorder := newDeviceRequestControlTestContext(t, 43, 94, 107, 1, nil)
	overLimit, overLimitRecorder := newDeviceRequestControlTestContext(t, 43, 94, 108, 1, nil)

	assert.True(t, enforceUserDeviceRateLimit(probe, false))
	assert.Equal(t, http.StatusOK, probeRecorder.Code)
	assert.True(t, enforceUserDeviceRateLimit(counted, true))
	assert.Equal(t, http.StatusOK, countedRecorder.Code)

	assert.False(t, enforceUserDeviceRateLimit(overLimit, true))
	assert.Equal(t, http.StatusTooManyRequests, overLimitRecorder.Code)
	assert.Equal(t, "rate_limit_exceeded", decodeDeviceRequestControlError(t, overLimitRecorder).Error.Code)
}

func TestEnforceUserDeviceRateLimitFallsBackToProcessMemoryWhenRedisUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	discardUserDeviceAccessStatsForTest(t)
	_, redisClient := useRateLimitMiniRedis(t)
	require.NoError(t, redisClient.Close())
	resetUserDeviceRateLimitFallbackForTest()
	t.Cleanup(resetUserDeviceRateLimitFallbackForTest)

	first, firstRecorder := newDeviceRequestControlTestContext(t, 44, 95, 109, 1, nil)
	second, secondRecorder := newDeviceRequestControlTestContext(t, 44, 95, 110, 1, nil)

	assert.True(t, enforceUserDeviceRateLimit(first, true))
	assert.Equal(t, http.StatusOK, firstRecorder.Code)
	assert.False(t, enforceUserDeviceRateLimit(second, true))
	assert.Equal(t, http.StatusTooManyRequests, secondRecorder.Code)
	assert.NotEmpty(t, secondRecorder.Header().Get("Retry-After"))
	assert.Equal(t, "rate_limit_exceeded", decodeDeviceRequestControlError(t, secondRecorder).Error.Code)
}

func TestUserDeviceRateLimitFallbackRejectsNewBucketAtCapacity(t *testing.T) {
	resetUserDeviceRateLimitFallbackForTest()
	t.Cleanup(resetUserDeviceRateLimitFallbackForTest)
	now := time.Unix(1_700_000_000, 0)

	userDeviceRateLimitFallbackMu.Lock()
	for i := range userDeviceRateLimitFallbackMax {
		expiresAt := now.Unix() + 30
		if i == 0 {
			expiresAt = now.Unix() + 15
		}
		userDeviceRateLimitFallback[fmt.Sprintf("active-%d", i)] = userDeviceRateLimitFallbackWindow{
			count:     1,
			expiresAt: expiresAt,
		}
	}
	userDeviceRateLimitFallbackMu.Unlock()

	allowed, retryAfter := takeUserDeviceRateLimitFallback("new-device", 2, now)

	assert.False(t, allowed)
	assert.EqualValues(t, 15, retryAfter)
	userDeviceRateLimitFallbackMu.Lock()
	assert.Len(t, userDeviceRateLimitFallback, userDeviceRateLimitFallbackMax)
	_, inserted := userDeviceRateLimitFallback["new-device"]
	userDeviceRateLimitFallbackMu.Unlock()
	assert.False(t, inserted)

	allowed, _ = takeUserDeviceRateLimitFallback("active-1", 2, now)
	assert.True(t, allowed)
}

func TestUserDeviceControlDenialsUseBatchedStatistics(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	require.NoError(t, service.FlushDeviceAccessStatsAt(time.Now()))
	user := createUserAPIAccessTestUser(t, "device-control-stats")
	devices := []model.UserDevice{
		{UserId: user.Id, Status: string(constant.UserDevicePending), BlockedModelsJSON: "[]"},
		{UserId: user.Id, Status: string(constant.UserDevicePending), BlockedModelsJSON: "[]"},
	}
	require.NoError(t, model.DB.Create(&devices).Error)

	blocked, _ := newDeviceRequestControlTestContext(t, user.Id, devices[0].Id, 0, 0, []string{"gpt-5.6-sol"})
	assert.False(t, enforceUserDeviceModelAccess(blocked, "gpt-5.6-sol"))

	resetUserDeviceRateLimitFallbackForTest()
	first, _ := newDeviceRequestControlTestContext(t, user.Id, devices[1].Id, 0, 1, nil)
	overLimit, _ := newDeviceRequestControlTestContext(t, user.Id, devices[1].Id, 0, 1, nil)
	assert.True(t, enforceUserDeviceRateLimit(first, true))
	assert.False(t, enforceUserDeviceRateLimit(overLimit, true))

	var before []model.UserDevice
	require.NoError(t, model.DB.Where("id IN ?", []int{devices[0].Id, devices[1].Id}).Order("id ASC").Find(&before).Error)
	require.Len(t, before, 2)
	assert.Zero(t, before[0].DeniedCount)
	assert.Zero(t, before[1].DeniedCount)

	require.NoError(t, service.FlushDeviceAccessStatsAt(time.Now()))
	var after []model.UserDevice
	require.NoError(t, model.DB.Where("id IN ?", []int{devices[0].Id, devices[1].Id}).Order("id ASC").Find(&after).Error)
	require.Len(t, after, 2)
	assert.EqualValues(t, 1, after[0].DeniedCount)
	assert.EqualValues(t, 1, after[1].DeniedCount)
}
