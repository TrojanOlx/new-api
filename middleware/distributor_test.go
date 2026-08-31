package middleware

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	taskdto "github.com/QuantumNous/new-api/dto"
	appI18n "github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/pkg/jsplugin"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChannelMatchesExpectedTaskPluginUsesGenericChannelSetting(t *testing.T) {
	channel := &model.Channel{Type: constant.ChannelTypeTaskPlugin}
	channel.SetSetting(dto.ChannelSettings{TaskPluginKey: "generic-alpha"})

	assert.True(t, channelMatchesExpectedTaskPlugin(nil, channel, "generic-alpha"))
	assert.False(t, channelMatchesExpectedTaskPlugin(nil, channel, "generic-beta"))
	assert.False(t, channelMatchesExpectedTaskPlugin(nil, channel, ""))
}

func TestChannelMatchesExpectedTaskPluginUsesPinnedLegacyIndex(t *testing.T) {
	registry := jsplugin.NewRegistry()
	alpha, err := registry.Register(distributorTaskPluginSource("legacy-alpha", constant.ChannelTypeKling), jsplugin.Options{})
	require.NoError(t, err)
	pinnedGeneration := registry.Generation()

	require.NoError(t, registry.Unregister("legacy-alpha"))
	_, err = registry.Register(distributorTaskPluginSource("legacy-beta", constant.ChannelTypeKling), jsplugin.Options{})
	require.NoError(t, err)

	c, _ := gin.CreateTestContext(nil)
	c.Set(jsplugin.ContextKeyPinnedPlugin, jsplugin.PinnedPlugin{
		Generation: pinnedGeneration,
		Plugin:     alpha,
	})
	channel := &model.Channel{Type: constant.ChannelTypeKling}

	assert.True(t, channelMatchesExpectedTaskPlugin(c, channel, "legacy-alpha"))
	assert.False(t, channelMatchesExpectedTaskPlugin(c, channel, "legacy-beta"))
	assert.False(t, channelMatchesExpectedTaskPlugin(c, &model.Channel{Type: constant.ChannelTypeJimeng}, "legacy-alpha"))
}

func TestChannelMatchesExpectedTaskPluginRejectsUnindexedLegacyChannel(t *testing.T) {
	registry := jsplugin.NewRegistry()
	plugin, err := registry.Register(distributorTaskPluginSource("legacy-alpha", constant.ChannelTypeKling), jsplugin.Options{})
	require.NoError(t, err)

	c, _ := gin.CreateTestContext(nil)
	c.Set(jsplugin.ContextKeyPinnedPlugin, jsplugin.PinnedPlugin{
		Generation: registry.Generation(),
		Plugin:     plugin,
	})

	assert.False(t, channelMatchesExpectedTaskPlugin(c, &model.Channel{Type: constant.ChannelTypeJimeng}, "legacy-alpha"))
	assert.False(t, channelMatchesExpectedTaskPlugin(c, &model.Channel{Type: 0}, "legacy-alpha"))
	assert.True(t, channelMatchesExpectedTaskPlugin(c, &model.Channel{Type: constant.ChannelTypeJimeng}, ""))
	assert.False(t, channelMatchesExpectedTaskPlugin(nil, &model.Channel{Type: constant.ChannelTypeKling}, "legacy-alpha"))

	c.Set("expected_task_plugin_key", "legacy-alpha")
	setupErr := SetupContextForSelectedChannel(c, &model.Channel{Type: constant.ChannelTypeJimeng}, "task-model")
	require.NotNil(t, setupErr)
	assert.Contains(t, setupErr.Error(), "does not match")
}

func TestSharedEndpointRebindsToSelectedLegacyProvider(t *testing.T) {
	registry := jsplugin.NewRegistry()
	_, err := registry.Register(distributorEndpointPluginSource("gemini-shared", constant.ChannelTypeGemini), jsplugin.Options{})
	require.NoError(t, err)
	_, err = registry.Register(distributorEndpointPluginSource("vertex-shared", constant.ChannelTypeVertexAi), jsplugin.Options{})
	require.NoError(t, err)
	candidates := registry.Generation().LookupEndpointCandidates("POST", "/v1/responses", "task-model")
	require.Len(t, candidates, 2)

	c, _ := gin.CreateTestContext(nil)
	c.Set(jsplugin.ContextKeyPinnedPlugin, jsplugin.PinnedPlugin{Generation: registry.Generation(), Plugin: candidates[0].Plugin})
	c.Set(jsplugin.ContextKeyPinnedEndpoint, jsplugin.PinnedEndpoint{
		Generation: registry.Generation(),
		Plugin:     candidates[0].Plugin,
		Protocol:   candidates[0].Protocol,
		Operation:  candidates[0].Operation,
		Model:      "task-model",
		Candidates: candidates,
	})
	c.Set("expected_task_plugin_key", candidates[0].Plugin.Meta.Key)

	geminiChannel := &model.Channel{Id: 1, Type: constant.ChannelTypeGemini}
	vertexChannel := &model.Channel{Id: 2, Type: constant.ChannelTypeVertexAi}
	assert.True(t, channelMatchesExpectedTaskPlugin(c, geminiChannel, candidates[0].Plugin.Meta.Key))
	assert.True(t, channelMatchesExpectedTaskPlugin(c, vertexChannel, candidates[0].Plugin.Meta.Key))
	assert.False(t, channelMatchesExpectedTaskPlugin(c, &model.Channel{Type: constant.ChannelTypeKling}, candidates[0].Plugin.Meta.Key))

	require.Nil(t, SetupContextForSelectedChannel(c, vertexChannel, "task-model"))
	pinnedValue, exists := c.Get(jsplugin.ContextKeyPinnedEndpoint)
	require.True(t, exists)
	pinned, ok := pinnedValue.(jsplugin.PinnedEndpoint)
	require.True(t, ok)
	assert.Equal(t, "vertex-shared", pinned.Plugin.Meta.Key)
	assert.Equal(t, "vertex-shared", c.GetString("expected_task_plugin_key"))
	assert.Equal(t, "vertex-shared", c.GetString("task_plugin_key"))
	assert.True(t, channelMatchesExpectedTaskPlugin(c, geminiChannel, "vertex-shared"), "a retry may select another declared provider")
}

func TestDistributeEnforcesModelControlsBeforePinnedChannel(t *testing.T) {
	discardUserDeviceAccessStatsForTest(t)
	t.Run("device blocked model", func(t *testing.T) {
		setupOriginTaskDB(t)
		channel := insertOriginTaskChannel(t, common.ChannelStatusEnabled)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/vendor/jobs", strings.NewReader(`{}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("resolved_task_model", "gpt-5.6-sol")
		common.SetContextKey(c, constant.ContextKeyUserId, 81)
		common.SetContextKey(c, constant.ContextKeyUserDeviceControls, service.UserDeviceRequestControls{
			DeviceId: 91, FingerprintId: 92, BlockedModels: []string{"gpt-5.6-sol"},
		})
		service.GetChannelConstraints(c).AddPin(taskdto.ChannelPin{
			ChannelId: channel.Id, Source: taskdto.PinSourceOriginTask,
			Rank: taskdto.PinRankOriginTask, RetryMode: taskdto.PinRetrySameChannel,
		})

		Distribute()(c)

		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusForbidden, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "access_denied")
		assert.Zero(t, common.GetContextKeyInt(c, constant.ContextKeyChannelId))
	})

	t.Run("token model limit", func(t *testing.T) {
		setupOriginTaskDB(t)
		channel := insertOriginTaskChannel(t, common.ChannelStatusEnabled)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/vendor/jobs", strings.NewReader(`{}`))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("resolved_task_model", "gpt-5.6-sol")
		common.SetContextKey(c, constant.ContextKeyUserId, 82)
		common.SetContextKey(c, constant.ContextKeyTokenModelLimitEnabled, true)
		common.SetContextKey(c, constant.ContextKeyTokenModelLimit, map[string]bool{"gpt-5.6-terra": true})
		common.SetContextKey(c, constant.ContextKeyUserDeviceControls, service.UserDeviceRequestControls{DeviceId: 93, FingerprintId: 94})
		service.GetChannelConstraints(c).AddPin(taskdto.ChannelPin{
			ChannelId: channel.Id, Source: taskdto.PinSourceOriginTask,
			Rank: taskdto.PinRankOriginTask, RetryMode: taskdto.PinRetrySameChannel,
		})

		Distribute()(c)

		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusForbidden, recorder.Code)
		assert.Zero(t, common.GetContextKeyInt(c, constant.ContextKeyChannelId))
	})
}

func TestDistributeAllowsTaskFetchForDeviceBlockedModel(t *testing.T) {
	require.NoError(t, appI18n.Init())
	setupOriginTaskDB(t)
	channel := insertOriginTaskChannel(t, common.ChannelStatusEnabled)
	task := insertOriginOwnedTask(t, "device-control-fetch", 81, channel.Id, "sora", "gpt-5.6-sol")

	for _, testCase := range []struct {
		name string
		path string
	}{
		{name: "OpenAI video", path: "/v1/videos/" + task.TaskID},
		{name: "legacy video generation", path: "/v1/video/generations/" + task.TaskID},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodGet, testCase.path, nil)
			c.Params = gin.Params{{Key: "task_id", Value: task.TaskID}}
			common.SetContextKey(c, constant.ContextKeyUserId, 81)
			common.SetContextKey(c, constant.ContextKeyUserDeviceControls, service.UserDeviceRequestControls{
				DeviceId: 91, FingerprintId: 92, BlockedModels: []string{"gpt-5.6-sol"},
			})

			Distribute()(c)

			assert.False(t, c.IsAborted())
			assert.Equal(t, http.StatusOK, recorder.Code)
		})
	}
}

func TestDistributeKeepsTokenModelLimitOnTaskFetch(t *testing.T) {
	require.NoError(t, appI18n.Init())
	setupOriginTaskDB(t)
	channel := insertOriginTaskChannel(t, common.ChannelStatusEnabled)
	task := insertOriginOwnedTask(t, "token-model-fetch", 82, channel.Id, "sora", "gpt-5.6-sol")

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/videos/"+task.TaskID, nil)
	c.Params = gin.Params{{Key: "task_id", Value: task.TaskID}}
	common.SetContextKey(c, constant.ContextKeyUserId, 82)
	common.SetContextKey(c, constant.ContextKeyTokenModelLimitEnabled, true)
	common.SetContextKey(c, constant.ContextKeyTokenModelLimit, map[string]bool{"gpt-5.6-terra": true})

	Distribute()(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestDistributeBlocksRemixForDeviceBlockedOriginModel(t *testing.T) {
	require.NoError(t, appI18n.Init())
	discardUserDeviceAccessStatsForTest(t)
	setupOriginTaskDB(t)
	channel := insertOriginTaskChannel(t, common.ChannelStatusEnabled)
	task := insertOriginOwnedTask(t, "device-control-remix-blocked", 83, channel.Id, "sora", "gpt-5.6-sol")

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/videos/"+task.TaskID+"/remix", nil)
	c.Params = gin.Params{{Key: "video_id", Value: task.TaskID}}
	common.SetContextKey(c, constant.ContextKeyUserId, 83)
	common.SetContextKey(c, constant.ContextKeyUserDeviceControls, service.UserDeviceRequestControls{
		DeviceId: 93, FingerprintId: 94, BlockedModels: []string{"gpt-5.6-sol"},
	})

	Distribute()(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "access_denied")
}

func TestGetModelRequestExtractsMultipartModelForLegacyEdits(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	require.NoError(t, writer.WriteField("model", "gpt-image-1"))
	require.NoError(t, writer.WriteField("prompt", "edit this image"))
	require.NoError(t, writer.Close())

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/edits", &body)
	c.Request.Header.Set("Content-Type", writer.FormDataContentType())

	request, shouldSelectChannel, err := getModelRequest(c)
	require.NoError(t, err)
	require.True(t, shouldSelectChannel)
	assert.Equal(t, "gpt-image-1", request.Model)
}

func TestGetModelRequestResolvesRemixOriginModelForDeviceControls(t *testing.T) {
	setupOriginTaskDB(t)
	channel := insertOriginTaskChannel(t, common.ChannelStatusEnabled)
	task := insertOriginOwnedTask(t, "device-control-remix", 81, channel.Id, "sora", "gpt-5.6-sol")
	persisted, exists, lookupErr := model.GetByTaskId(81, task.TaskID)
	require.NoError(t, lookupErr)
	require.True(t, exists)
	assert.Equal(t, "gpt-5.6-sol", persisted.Properties.OriginModelName)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/videos/"+task.TaskID+"/remix", nil)
	c.Params = gin.Params{{Key: "video_id", Value: task.TaskID}}
	common.SetContextKey(c, constant.ContextKeyUserId, 81)
	common.SetContextKey(c, constant.ContextKeyUserDeviceControls, service.UserDeviceRequestControls{DeviceId: 91})

	request, shouldSelectChannel, err := getModelRequest(c)
	require.NoError(t, err)
	require.False(t, shouldSelectChannel)
	assert.Equal(t, "gpt-5.6-sol", request.Model)
}

func TestUserDeviceModelNamePrefersOriginalClientModelOverResolvedPluginModel(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("resolved_task_model", "canonical-model")
	common.SetContextKey(c, constant.ContextKeyClientModel, "client-alias")

	assert.Equal(t, "client-alias", userDeviceModelName(c, "canonical-model"))
}

func TestShouldCountUserDeviceRequest(t *testing.T) {
	for _, testCase := range []struct {
		name                string
		method              string
		path                string
		shouldSelectChannel bool
		relayMode           int
		want                bool
	}{
		{name: "responses create", method: http.MethodPost, path: "/v1/responses", shouldSelectChannel: true, want: true},
		{name: "image generation", method: http.MethodPost, path: "/v1/images/generations", shouldSelectChannel: true, want: true},
		{name: "websocket handshake", method: http.MethodGet, path: "/v1/realtime", shouldSelectChannel: true, want: true},
		{name: "task fetch", method: http.MethodGet, path: "/v1/videos/task-1", relayMode: relayconstant.RelayModeVideoFetchByID, want: false},
		{name: "task list query", method: http.MethodPost, path: "/mj/task/list-by-condition", relayMode: relayconstant.RelayModeMidjourneyTaskFetchByCondition, want: false},
		{name: "video remix", method: http.MethodPost, path: "/v1/videos/video-1/remix", relayMode: relayconstant.RelayModeVideoSubmit, want: true},
		{name: "unsupported image variation", method: http.MethodPost, path: "/v1/images/variations", shouldSelectChannel: true, want: false},
		{name: "unsupported file upload", method: http.MethodPost, path: "/v1/files", shouldSelectChannel: true, want: false},
		{name: "unsupported fine tune", method: http.MethodPost, path: "/v1/fine-tunes", shouldSelectChannel: true, want: false},
		{name: "unsupported fine tune cancel", method: http.MethodPost, path: "/v1/fine-tunes/:id/cancel", shouldSelectChannel: true, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(testCase.method, testCase.path, nil)
			if testCase.relayMode != 0 {
				c.Set("relay_mode", testCase.relayMode)
			}
			assert.Equal(t, testCase.want, shouldCountUserDeviceRequest(c, testCase.shouldSelectChannel))
		})
	}
}

func distributorTaskPluginSource(key string, channelType int) string {
	return fmt.Sprintf(`
export const meta = {
  apiVersion: 1,
  key: %q,
  name: %q,
  version: "1.0.0",
  author: {name: "Test"},
  channelTypes: [%d],
  models: ["task-model"],
  fetchMode: "per_task",
};
export function buildSubmitRequest() { return {}; }
export function parseSubmitResponse() { return {taskId: "task"}; }
export function buildQueryRequest() { return {}; }
export function parseTaskResult() { return {status: "SUCCESS"}; }
`, key, key, channelType)
}

func distributorEndpointPluginSource(key string, channelType int) string {
	return fmt.Sprintf(`
export const meta = {
  apiVersion: 1,
  key: %q,
  name: %q,
  version: "1.0.0",
  author: {name: "Test"},
  channelTypes: [%d],
  models: ["task-model"],
  fetchMode: "per_task",
  protocols: [{name: "openai_responses", supports: ["stream", "sync", "background"]}],
};
export function buildSubmitRequest() { return {}; }
export function parseSubmitResponse() { return {taskId: "task"}; }
export function buildQueryRequest() { return {}; }
export function parseTaskResult() { return {status: "SUCCESS"}; }
export const protocols = {openai_responses: {
  decodeRequest: function(ctx) { return {kind: "submit", model: "task-model", requestBody: ctx.body.value}; },
  renderEvents: function() { return {events: [], state: null, done: false}; },
  renderFinal: function() { return {output: []}; },
}};
`, key, key, channelType)
}
