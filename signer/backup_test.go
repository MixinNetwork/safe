package signer

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/stretchr/testify/require"
)

type backupRoundTripper func(*http.Request) (*http.Response, error)

func (f backupRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type backupResponseBody struct {
	io.Reader
	closed bool
}

func (b *backupResponseBody) Close() error {
	b.closed = true
	return nil
}

func TestBackupClosesFailedResponseAndPreservesContext(t *testing.T) {
	key := crypto.NewKeyFromSeed(make([]byte, 64))
	node := &Node{conf: &Configuration{SaverAPI: "https://backup.example.test"}, saverKey: &key}
	op := &common.Operation{Id: "10000000-0000-4000-8000-000000000001", Curve: common.CurveEdwards25519Default}
	body := &backupResponseBody{Reader: strings.NewReader("failed")}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	node.backupClient = &http.Client{Transport: backupRoundTripper(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, ctx, r.Context())
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		return &http.Response{StatusCode: http.StatusInternalServerError, Status: "500 Internal Server Error", Body: body}, nil
	})}
	ok, err := node.sendKeygenBackup(ctx, op, []byte("share"))
	require.Error(t, err)
	require.False(t, ok)
	require.True(t, body.closed)
}
