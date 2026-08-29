package types

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessControlUnavailableErrorCodeIsOpenAICompatible(t *testing.T) {
	require.Equal(t, ErrorCode("access_control_unavailable"), ErrorCodeAccessControlUnavailable)

	err := InitOpenAIError(ErrorCodeAccessControlUnavailable, http.StatusServiceUnavailable)
	require.Equal(t, ErrorCodeAccessControlUnavailable, err.GetErrorCode())
	assert.Equal(t, http.StatusServiceUnavailable, err.StatusCode)

	openAIError := err.ToOpenAIError()
	assert.Equal(t, "access_control_unavailable", openAIError.Type)
	assert.Equal(t, ErrorCodeAccessControlUnavailable, openAIError.Code)
}
