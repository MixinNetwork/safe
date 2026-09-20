package util

import (
	"context"
	"errors"
	"fmt"
	"testing"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	mixin "github.com/fox-one/mixin-sdk-go/v3"
	"github.com/stretchr/testify/require"
)

type coverageCloser struct {
	err    error
	closed bool
}

func (c *coverageCloser) Close() error {
	c.closed = true
	return c.err
}

func TestSplitIDsRejectsNonCanonicalLists(t *testing.T) {
	require.Panics(t, func() { SplitIds(" leading", ",") })
	require.Panics(t, func() { SplitIds("trailing ", ",") })
	require.Panics(t, func() { SplitIds("one,,two", ",") })
	require.Panics(t, func() { SplitIds("one, ,two", ",") })
	require.Equal(t, []string{"one", "two"}, SplitIds("one,two", ","))
}

func TestIsErrorCodesSupportsBothMixinClients(t *testing.T) {
	require.False(t, IsErrorCodes(nil, 1))
	require.False(t, IsErrorCodes(errors.New("plain"), 1))

	sdkError := fmt.Errorf("wrapped: %w", &mixin.Error{Code: 20119})
	require.True(t, IsErrorCodes(sdkError, 1, 20119))
	require.False(t, IsErrorCodes(sdkError, 1, 2))

	botError := fmt.Errorf("wrapped: %w", bot.Error{Code: 7000})
	require.True(t, IsErrorCodes(botError, 7000))
	require.False(t, IsErrorCodes(botError, 7001))
}

func TestCloseOrPanic(t *testing.T) {
	closer := &coverageCloser{}
	CloseOrPanic(closer)
	require.True(t, closer.closed)

	closer = &coverageCloser{err: errors.New("close failed")}
	require.PanicsWithError(t, "close failed", func() { CloseOrPanic(closer) })
	require.True(t, closer.closed)
}

func TestEnvironmentContext(t *testing.T) {
	ctx := context.Background()
	require.False(t, CheckTestEnvironment(ctx))
	require.False(t, CheckTestEnvironment(context.WithValue(ctx, contextKeyEnvironment, 1)))
	require.False(t, CheckTestEnvironment(context.WithValue(ctx, contextKeyEnvironment, "production")))
	require.True(t, CheckTestEnvironment(EnableTestEnvironment(ctx)))
}
