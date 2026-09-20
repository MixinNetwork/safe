package observer

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/MixinNetwork/safe/common"
	keeperstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/shopspring/decimal"
)

// FuzzObserverHTTPPostRequests sends arbitrary user-controlled bodies and
// route parameters through every public POST handler. Missing object IDs keep
// the test isolated from transaction side effects while still exercising the
// real JSON decoding, routing parameters, response rendering, and SQL lookups.
func FuzzObserverHTTPPostRequests(f *testing.F) {
	root := f.TempDir()
	observerStore, err := OpenSQLite3Store(filepath.Join(root, "observer.sqlite3"))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = observerStore.Close() })
	keeperStore, err := keeperstore.OpenSQLite3Store(filepath.Join(root, "keeper.sqlite3"))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = keeperStore.Close() })

	node := &Node{
		conf:        &Configuration{},
		store:       observerStore,
		keeperStore: keeperStore,
	}
	f.Add(byte(0), []byte(`{"action":"approve","address":"missing","signature":"invalid"}`), "missing")
	f.Add(byte(1), []byte(`{"action":"close","hash":"missing","id":"missing","signature":"invalid"}`), "missing")
	f.Add(byte(2), []byte(`{"chain":1,"action":"approve","raw":"invalid"}`), "missing")
	f.Add(byte(3), []byte(`{"holder":"missing","hash":"missing","raw":"invalid"}`), "missing")
	f.Add(byte(0), []byte("{"), "")
	f.Add(byte(2), []byte{}, "\x00")

	f.Fuzz(func(t *testing.T, endpoint byte, body []byte, id string) {
		if len(body) > 64<<10 || len(id) > 4<<10 {
			t.Skip()
		}
		req := httptest.NewRequest(http.MethodPost, "http://observer.invalid/", bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		params := map[string]string{"id": id}

		switch endpoint % 4 {
		case 0:
			node.httpApproveAccount(recorder, req, params)
		case 1:
			node.httpSignRecovery(recorder, req, params)
		case 2:
			node.httpApproveTransaction(recorder, req, params)
		case 3:
			node.httpCreateInheritanceTransaction(recorder, req, nil)
		}

		if recorder.Code < 100 || recorder.Code > 599 {
			t.Fatalf("invalid HTTP status %d", recorder.Code)
		}
	})
}

// FuzzObserverCustomKeySnapshot exercises the memo controlled by a user who
// pays for custom-observer-key registration. The unpaid amount intentionally
// stops processing after validation, before any keeper request can be sent.
func FuzzObserverCustomKeySnapshot(f *testing.F) {
	node := &Node{conf: &Configuration{
		CustomKeyPriceAssetId: "custom-key-price-asset",
		CustomKeyPriceAmount:  "1",
	}}
	bitcoinMemo := make([]byte, 66)
	bitcoinMemo[0] = common.CurveSecp256k1ECDSABitcoin
	ethereumMemo := make([]byte, 66)
	ethereumMemo[0] = common.CurveSecp256k1ECDSAEthereum
	f.Add(byte(1), bitcoinMemo)
	f.Add(byte(1), ethereumMemo)
	f.Add(byte(1), make([]byte, 65))
	f.Add(byte(0), []byte("%%%"))

	f.Fuzz(func(t *testing.T, mode byte, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		memo := string(data)
		if mode%2 == 1 {
			memo = base64.RawURLEncoding.EncodeToString(data)
		}
		snapshot := &mixin.SafeSnapshot{
			AssetID: node.conf.CustomKeyPriceAssetId,
			Amount:  decimal.Zero,
			Memo:    memo,
		}
		handled, err := node.handleCustomObserverKeyRegistration(t.Context(), snapshot)
		if err != nil {
			t.Fatalf("snapshot memo returned an error: %v", err)
		}

		decoded, decodeErr := base64.RawURLEncoding.DecodeString(memo)
		valid := decodeErr == nil && len(decoded) == 66 &&
			(decoded[0] == common.CurveSecp256k1ECDSABitcoin || decoded[0] == common.CurveSecp256k1ECDSAEthereum)
		if handled != valid {
			t.Fatalf("handled=%t for valid=%t memo", handled, valid)
		}
	})
}
