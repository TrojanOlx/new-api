package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type userAccessErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func setupUserAPIAccessMiddlewareTest(t *testing.T) *gorm.DB {
	t.Helper()
	previousDB, previousRedis, previousRDB := model.DB, common.RedisEnabled, common.RDB
	previousType := common.MainDatabaseType()
	previousSecret := common.DeviceFingerprintSecret
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.Token{}, &model.UserSession{},
		&model.UserDevice{}, &model.UserDeviceFingerprint{}, &model.UserDeviceIP{},
	))
	model.DB = db
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	common.RDB = nil
	common.DeviceFingerprintSecret = "middleware-device-secret-0123456789abcdef"
	gin.SetMode(gin.TestMode)
	t.Cleanup(func() {
		model.DB, common.RedisEnabled, common.RDB = previousDB, previousRedis, previousRDB
		common.SetMainDatabaseType(previousType)
		common.DeviceFingerprintSecret = previousSecret
		_ = sqlDB.Close()
	})
	return db
}

func createUserAPIAccessTestUser(t *testing.T, username string) *model.User {
	t.Helper()
	user := &model.User{
		Username: username, Password: "unused", Group: "default", AffCode: "aff-" + username,
		Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		AuthVersion: 1, AccessPolicyVersion: 1,
		APIIPMode: string(constant.UserIPPolicyUnrestricted), APIIPAllowlist: "[]",
		DevicePolicyMode: string(constant.UserDevicePolicyOff),
	}
	require.NoError(t, model.DB.Create(user).Error)
	return user
}

func createUserAPIAccessTestToken(t *testing.T, userID int, key string, allowIPs string) *model.Token {
	t.Helper()
	allowIPsCopy := allowIPs
	token := &model.Token{
		UserId: userID, Key: key, Name: key, Status: common.TokenStatusEnabled,
		CreatedTime: time.Now().Unix(), ExpiredTime: -1, UnlimitedQuota: true,
	}
	if allowIPs != "" {
		token.AllowIps = &allowIPsCopy
	}
	require.NoError(t, model.DB.Create(token).Error)
	return token
}

func newUserAPIAccessRouter(t *testing.T, middleware gin.HandlerFunc) *gin.Engine {
	t.Helper()
	t.Setenv("TRUSTED_PROXIES", "192.0.2.0/24")
	router := gin.New()
	require.NoError(t, ConfigureTrustedProxies(router))
	router.GET("/protected", middleware, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user_id": c.GetInt("id")})
	})
	return router
}

func requestUserAPIAccess(router http.Handler, key string, remoteAddr string, forwardedFor string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.RemoteAddr = remoteAddr
	request.Header.Set("Authorization", "Bearer sk-"+key)
	if forwardedFor != "" {
		request.Header.Set("X-Forwarded-For", forwardedFor)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func decodeUserAccessError(t *testing.T, response *httptest.ResponseRecorder) userAccessErrorResponse {
	t.Helper()
	var body userAccessErrorResponse
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
	return body
}

func TestTokenAuthOldAndNewKeysInheritUserIPPolicy(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	user := createUserAPIAccessTestUser(t, "old-new-keys")
	createUserAPIAccessTestToken(t, user.Id, "oldkeyone", "")
	createUserAPIAccessTestToken(t, user.Id, "oldkeytwo", "")
	mode := string(constant.UserIPPolicyAllowlist)
	allowlist := `["203.0.113.10"]`
	_, changed, err := model.UpdateUserAccessPolicy(user.Id, model.UserAccessPolicyPatch{IPMode: &mode, IPAllowlistJSON: &allowlist})
	require.NoError(t, err)
	require.True(t, changed)
	createUserAPIAccessTestToken(t, user.Id, "newkeyone", "")
	router := newUserAPIAccessRouter(t, TokenAuth())

	for _, key := range []string{"oldkeyone", "oldkeytwo", "newkeyone"} {
		response := requestUserAPIAccess(router, key, "192.0.2.10:1234", "198.51.100.10", nil)
		assert.Equal(t, http.StatusForbidden, response.Code)
		assert.Equal(t, string(types.ErrorCodeAccessDenied), decodeUserAccessError(t, response).Error.Code)
	}
}

func TestTokenAuthIntersectsUserAndTokenIPAllowlists(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	user := createUserAPIAccessTestUser(t, "intersect-ip")
	mode := string(constant.UserIPPolicyAllowlist)
	allowlist := `["203.0.113.0/24"]`
	_, _, err := model.UpdateUserAccessPolicy(user.Id, model.UserAccessPolicyPatch{IPMode: &mode, IPAllowlistJSON: &allowlist})
	require.NoError(t, err)
	createUserAPIAccessTestToken(t, user.Id, "intersectionkey", "203.0.113.10")
	router := newUserAPIAccessRouter(t, TokenAuth())

	allowed := requestUserAPIAccess(router, "intersectionkey", "192.0.2.10:1234", "203.0.113.10", nil)
	assert.Equal(t, http.StatusOK, allowed.Code)
	deniedByToken := requestUserAPIAccess(router, "intersectionkey", "192.0.2.10:1234", "203.0.113.20", nil)
	assert.Equal(t, http.StatusForbidden, deniedByToken.Code)
	assert.Equal(t, string(types.ErrorCodeAccessDenied), decodeUserAccessError(t, deniedByToken).Error.Code)
}

func TestTokenAuthReadOnlyEnforcesUserAndTokenIPPolicy(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	user := createUserAPIAccessTestUser(t, "read-only-policy")
	mode := string(constant.UserIPPolicyAllowlist)
	allowlist := `["203.0.113.10"]`
	_, _, err := model.UpdateUserAccessPolicy(user.Id, model.UserAccessPolicyPatch{IPMode: &mode, IPAllowlistJSON: &allowlist})
	require.NoError(t, err)
	createUserAPIAccessTestToken(t, user.Id, "readonlykey", "203.0.113.10")
	router := newUserAPIAccessRouter(t, TokenAuthReadOnly())

	response := requestUserAPIAccess(router, "readonlykey", "192.0.2.10:1234", "203.0.113.20", nil)
	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.Equal(t, string(types.ErrorCodeAccessDenied), decodeUserAccessError(t, response).Error.Code)
}

func TestUserAuthDoesNotApplyAPIAccessPolicy(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	user := createUserAPIAccessTestUser(t, "dashboard-bypass")
	pat := "dashboard-pat"
	mode := string(constant.UserIPPolicyAllowlist)
	allowlist := `["203.0.113.10"]`
	deviceMode := string(constant.UserDevicePolicyAllowlist)
	_, _, err := model.UpdateUserAccessPolicy(user.Id, model.UserAccessPolicyPatch{
		IPMode: &mode, IPAllowlistJSON: &allowlist, DeviceMode: &deviceMode,
	})
	require.NoError(t, err)
	require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", user.Id).Update("access_token", pat).Error)
	router := newUserAPIAccessRouter(t, UserAuth())

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("Authorization", "Bearer "+pat)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)
}

func TestTokenAuthUsesTrustedForwardedIPAndRejectsSpoofedForwardedIP(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	user := createUserAPIAccessTestUser(t, "trusted-forwarded-ip")
	mode := string(constant.UserIPPolicyAllowlist)
	allowlist := `["203.0.113.10"]`
	_, _, err := model.UpdateUserAccessPolicy(user.Id, model.UserAccessPolicyPatch{IPMode: &mode, IPAllowlistJSON: &allowlist})
	require.NoError(t, err)
	createUserAPIAccessTestToken(t, user.Id, "forwardedkey", "")
	router := newUserAPIAccessRouter(t, TokenAuth())

	trusted := requestUserAPIAccess(router, "forwardedkey", "192.0.2.10:1234", "203.0.113.10", nil)
	assert.Equal(t, http.StatusOK, trusted.Code)
	spoofed := requestUserAPIAccess(router, "forwardedkey", "198.51.100.10:1234", "203.0.113.10", nil)
	assert.Equal(t, http.StatusForbidden, spoofed.Code)
}

func TestTokenAuthMapsAccessFenceAndDeviceDependencyTo503(t *testing.T) {
	t.Run("pending access fence", func(t *testing.T) {
		setupUserAPIAccessMiddlewareTest(t)
		user := createUserAPIAccessTestUser(t, "pending-fence")
		createUserAPIAccessTestToken(t, user.Id, "pendingfencekey", "")
		server := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: server.Addr()})
		previousRedis, previousRDB := common.RedisEnabled, common.RDB
		common.RedisEnabled, common.RDB = true, client
		t.Cleanup(func() {
			_ = client.Close()
			common.RedisEnabled, common.RDB = previousRedis, previousRDB
		})
		require.NoError(t, model.SetUserAccessPolicyVersionFence(user.Id, user.AccessPolicyVersion+1))
		router := newUserAPIAccessRouter(t, TokenAuth())

		response := requestUserAPIAccess(router, "pendingfencekey", "192.0.2.10:1234", "203.0.113.10", nil)
		assert.Equal(t, http.StatusServiceUnavailable, response.Code)
		assert.Equal(t, "3", response.Header().Get("Retry-After"))
		assert.Equal(t, string(types.ErrorCodeAccessControlUnavailable), decodeUserAccessError(t, response).Error.Code)
	})

	t.Run("fingerprint secret unavailable", func(t *testing.T) {
		setupUserAPIAccessMiddlewareTest(t)
		common.DeviceFingerprintSecret = ""
		user := createUserAPIAccessTestUser(t, "missing-device-secret")
		deviceMode := string(constant.UserDevicePolicyAllowlist)
		_, _, err := model.UpdateUserAccessPolicy(user.Id, model.UserAccessPolicyPatch{DeviceMode: &deviceMode})
		require.NoError(t, err)
		createUserAPIAccessTestToken(t, user.Id, "missingsecretkey", "")
		router := newUserAPIAccessRouter(t, TokenAuth())

		response := requestUserAPIAccess(router, "missingsecretkey", "192.0.2.10:1234", "203.0.113.10", nil)
		assert.Equal(t, http.StatusServiceUnavailable, response.Code)
		assert.Equal(t, "3", response.Header().Get("Retry-After"))
		assert.Equal(t, string(types.ErrorCodeAccessControlUnavailable), decodeUserAccessError(t, response).Error.Code)
	})
}

func TestContinueWithUserDeviceActivityRenewsUntilDownstreamReturns(t *testing.T) {
	previousInterval := userDeviceActivityLeaseInterval
	previousTouch := touchUserDeviceNetworkActivity
	userDeviceActivityLeaseInterval = time.Millisecond
	touchCalled := make(chan struct{}, 1)
	touchUserDeviceNetworkActivity = func(userID, deviceID int, ipHash string, now time.Time) bool {
		assert.Equal(t, 11, userID)
		assert.Equal(t, 22, deviceID)
		assert.Equal(t, "ip-hash", ipHash)
		select {
		case touchCalled <- struct{}{}:
		default:
		}
		return true
	}
	t.Cleanup(func() {
		userDeviceActivityLeaseInterval = previousInterval
		touchUserDeviceNetworkActivity = previousTouch
	})

	downstreamStarted := make(chan struct{})
	allowDownstreamReturn := make(chan struct{})
	released := make(chan struct{})
	requestDone := make(chan struct{})
	router := gin.New()
	router.GET("/lease",
		func(c *gin.Context) {
			continueWithUserDeviceActivity(c, userDeviceActivity{
				userID: 11, deviceID: 22, ipHash: "ip-hash",
				release: func() { close(released) },
			})
		},
		func(c *gin.Context) {
			close(downstreamStarted)
			<-allowDownstreamReturn
			c.Status(http.StatusNoContent)
		},
	)

	go func() {
		request := httptest.NewRequest(http.MethodGet, "/lease", nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		assert.Equal(t, http.StatusNoContent, response.Code)
		close(requestDone)
	}()

	select {
	case <-downstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("downstream handler did not start")
	}
	select {
	case <-touchCalled:
	case <-time.After(time.Second):
		t.Fatal("device activity lease was not renewed")
	}
	select {
	case <-released:
		t.Fatal("device activity was released before downstream returned")
	default:
	}
	close(allowDownstreamReturn)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not finish")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("device activity was not released")
	}
}

func TestTokenAuthReleasesDeviceActivityWhenLaterTokenValidationFails(t *testing.T) {
	setupUserAPIAccessMiddlewareTest(t)
	user := createUserAPIAccessTestUser(t, "release-on-token-failure")
	createUserAPIAccessTestToken(t, user.Id, "releasekey", "")

	previousEvaluate := evaluateUserAPIAccessForMiddleware
	released := make(chan struct{})
	evaluateUserAPIAccessForMiddleware = func(*model.UserBase, netip.Addr, service.DeviceRequestMetadata, time.Time) service.UserAccessResult {
		return service.UserAccessResult{
			Decision: service.UserAccessAllow,
			DeviceId: 99,
			Release:  func() { close(released) },
		}
	}
	t.Cleanup(func() { evaluateUserAPIAccessForMiddleware = previousEvaluate })

	router := newUserAPIAccessRouter(t, TokenAuth())
	response := requestUserAPIAccess(router, "releasekey-123", "192.0.2.10:1234", "203.0.113.10", nil)
	require.Equal(t, http.StatusForbidden, response.Code)
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("device activity was not released after token validation failed")
	}
}

func TestEnforceUserAPIAccessStoresResolvedDeviceControls(t *testing.T) {
	previousEvaluate := evaluateUserAPIAccessForMiddleware
	evaluateUserAPIAccessForMiddleware = func(*model.UserBase, netip.Addr, service.DeviceRequestMetadata, time.Time) service.UserAccessResult {
		return service.UserAccessResult{
			Decision:      service.UserAccessAllow,
			DeviceId:      91,
			FingerprintId: 92,
			RateLimitRPM:  30,
			BlockedModels: []string{"gpt-5.6-sol"},
		}
	}
	t.Cleanup(func() { evaluateUserAPIAccessForMiddleware = previousEvaluate })

	router := gin.New()
	router.GET("/controls", func(c *gin.Context) {
		require.True(t, enforceUserAPIAccess(c, &model.UserBase{Id: 90}))
		value, found := c.Get(string(constant.ContextKeyUserDeviceControls))
		require.True(t, found)
		controls, ok := value.(service.UserDeviceRequestControls)
		require.True(t, ok)
		assert.Equal(t, 91, controls.DeviceId)
		assert.Equal(t, 92, controls.FingerprintId)
		assert.Equal(t, 30, controls.RateLimitRPM)
		assert.Equal(t, []string{"gpt-5.6-sol"}, controls.BlockedModels)
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/controls", nil)
	request.RemoteAddr = "192.0.2.90:1234"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assert.Equal(t, http.StatusNoContent, response.Code)
}
