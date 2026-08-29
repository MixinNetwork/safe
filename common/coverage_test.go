package common

import (
	"bytes"
	"context"
	"encoding"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	mixincommon "github.com/MixinNetwork/mixin/common"
	mixincrypto "github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/fox-one/mixin-sdk-go/v3/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

type coverageBinaryMarshaler struct {
	b   []byte
	err error
}

var _ encoding.BinaryMarshaler = coverageBinaryMarshaler{}

func (m coverageBinaryMarshaler) MarshalBinary() ([]byte, error) {
	return m.b, m.err
}

func TestCoverageAESAndECDH(t *testing.T) {
	left := mixincrypto.NewKeyFromSeed(bytes.Repeat([]byte{1}, 64))
	right := mixincrypto.NewKeyFromSeed(bytes.Repeat([]byte{2}, 64))
	leftSecret := ECDHEd25519(left.String(), right.Public().String())
	rightSecret := ECDHEd25519(right.String(), left.Public().String())
	require.Equal(t, leftSecret, rightSecret)
	require.Panics(t, func() { ECDHEd25519("invalid", right.Public().String()) })
	require.Panics(t, func() { ECDHEd25519(left.String(), "invalid") })

	sid := uuid.Must(uuid.NewV4()).String()
	plain := append(uuid.Must(uuid.FromString(sid)).Bytes(), []byte("authenticated payload")...)
	ciphertext := AESEncrypt(leftSecret[:], plain, sid)
	require.NotEqual(t, plain, ciphertext)
	require.Equal(t, plain, AESDecrypt(leftSecret[:], ciphertext))

	require.Panics(t, func() { AESEncrypt(leftSecret[:], []byte("short"), sid) })
	require.Panics(t, func() { AESEncrypt(leftSecret[:], plain, uuid.Must(uuid.NewV4()).String()) })
	require.Panics(t, func() { AESEncrypt([]byte("short"), plain, sid) })
	require.Panics(t, func() { AESDecrypt([]byte("short"), ciphertext) })
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 1
	require.Panics(t, func() { AESDecrypt(leftSecret[:], tampered) })
}

func TestCoverageBase91(t *testing.T) {
	inputs := [][]byte{
		{},
		{0},
		{0, 0},
		[]byte("Mixin Safe"),
		bytes.Repeat([]byte{0xff}, 257),
	}
	for _, input := range inputs {
		encoded := Base91Encode(input)
		require.LessOrEqual(t, len(encoded), std.EncodedLen(len(input)))
		decoded, err := Base91Decode(encoded)
		require.NoError(t, err)
		require.Equal(t, input, decoded)
		require.GreaterOrEqual(t, std.DecodedLen(len(encoded)), len(input))
	}

	decoded, err := Base91Decode("A A")
	require.Error(t, err)
	require.Nil(t, decoded)
	dst := make([]byte, 16)
	n, err := std.Decode(dst, []byte("AA A"))
	require.Error(t, err)
	require.GreaterOrEqual(t, n, 0)
}

func TestCoverageChainMappings(t *testing.T) {
	tests := []struct {
		curve   byte
		chain   byte
		assetID string
	}{
		{CurveSecp256k1ECDSABitcoin, SafeChainBitcoin, SafeBitcoinChainId},
		{CurveSecp256k1ECDSALitecoin, SafeChainLitecoin, SafeLitecoinChainId},
		{CurveSecp256k1ECDSAEthereum, SafeChainEthereum, SafeEthereumChainId},
		{CurveSecp256k1ECDSAPolygon, SafeChainPolygon, SafePolygonChainId},
	}
	for _, test := range tests {
		require.Equal(t, test.chain, SafeCurveChain(test.curve))
		require.Equal(t, test.curve, SafeChainCurve(test.chain))
		require.Equal(t, test.assetID, SafeChainAssetId(test.chain))
		require.Equal(t, test.chain, SafeAssetIdChain(test.assetID))
		require.Equal(t, test.chain, SafeAssetIdChainNoPanic(test.assetID))
	}
	require.Zero(t, SafeAssetIdChainNoPanic("unknown"))
	require.Panics(t, func() { SafeCurveChain(0xff) })
	require.Panics(t, func() { SafeChainCurve(0xff) })
	require.Panics(t, func() { SafeChainAssetId(0xff) })
	require.Panics(t, func() { SafeAssetIdChain("unknown") })
}

func TestCoverageHTTPHelpers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	w := httptest.NewRecorder()
	RenderJSON(w, req, http.StatusCreated, map[string]string{"ok": "yes"})
	require.Equal(t, http.StatusCreated, w.Code)
	require.Equal(t, "application/json; charset=UTF-8", w.Header().Get("Content-Type"))
	require.JSONEq(t, `{"ok":"yes"}`, w.Body.String())

	w = httptest.NewRecorder()
	RenderError(w, req, errors.New("boom"))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.JSONEq(t, `{"error":"500"}`, w.Body.String())

	w = httptest.NewRecorder()
	HandlePanic(w, req, "panic")
	require.Equal(t, http.StatusInternalServerError, w.Code)

	w = httptest.NewRecorder()
	HandleNotFound(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)

	called := 0
	handler := HandleCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, 1, called)

	preflight := httptest.NewRequest(http.MethodOptions, "/", nil)
	preflight.Header.Set("Origin", "https://safe.example")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, preflight)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "https://safe.example", w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "OPTIONS,GET,POST,DELETE", w.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, 1, called)

	corsRequest := httptest.NewRequest(http.MethodPost, "/", nil)
	corsRequest.Header.Set("Origin", "https://safe.example")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, corsRequest)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, 2, called)
}

func TestCoverageMixinPureHelpers(t *testing.T) {
	general := mixincommon.ExtraSizeGeneralLimit
	storage := func(amount string) mixinnet.Transaction {
		return mixinnet.Transaction{
			Asset: mixinnet.XINAssetId,
			Outputs: []*mixinnet.Output{{
				Type:   mixinnet.OutputTypeScript,
				Amount: mixinnet.IntegerFromString(amount),
				Keys:   []mixinnet.Key{{1}},
				Script: mixinnet.Script{mixinnet.OperatorCmp, mixinnet.OperatorSum, mixinnet.Operator64},
			}},
		}
	}

	var tx mixinnet.Transaction
	require.Equal(t, general, ExtraLimit(tx))
	tx.Asset = mixinnet.XINAssetId
	require.Equal(t, general, ExtraLimit(tx))
	tx = storage(mixincommon.ExtraStoragePriceStep)
	require.Equal(t, mixincommon.ExtraSizeStorageStep, ExtraLimit(tx))
	tx.Outputs[0].Keys = nil
	require.Equal(t, general, ExtraLimit(tx))
	tx = storage(mixincommon.ExtraStoragePriceStep)
	tx.Outputs[0].Type = mixinnet.OutputTypeWithdrawalSubmit
	require.Equal(t, general, ExtraLimit(tx))
	tx = storage(mixincommon.ExtraStoragePriceStep)
	tx.Outputs[0].Script = mixinnet.NewThresholdScript(1)
	require.Equal(t, general, ExtraLimit(tx))
	tx = storage("0.00001")
	require.Equal(t, general, ExtraLimit(tx))
	tx = storage("1000")
	require.Equal(t, mixincommon.ExtraSizeStorageCapacity, ExtraLimit(tx))

	buildRaw := func(extra string) string {
		v := mixincommon.NewTransactionV5(mixincrypto.Sha256Hash([]byte("asset")))
		v.AddInput(mixincrypto.Sha256Hash([]byte("input")), 0)
		v.Extra = []byte(extra)
		return hex.EncodeToString(v.AsVersioned().Marshal())
	}
	raw := buildRaw("expected")
	req := &mixin.SafeTransactionRequest{RequestID: uuid.Must(uuid.NewV4()).String(), RawTransaction: raw}
	require.NoError(t, checkTransactionRequestRaw(req, raw))
	require.Error(t, checkTransactionRequestRaw(req, "zz"))
	require.Error(t, checkTransactionRequestRaw(req, "00"))
	req.RawTransaction = "zz"
	require.Error(t, checkTransactionRequestRaw(req, raw))
	req.RawTransaction = "00"
	require.Error(t, checkTransactionRequestRaw(req, raw))
	req.RawTransaction = buildRaw("different")
	require.ErrorContains(t, checkTransactionRequestRaw(req, raw), "raw transaction mismatch")

	ctx := EnableTestEnvironment(context.Background())
	hash, err := SafeReadWithdrawalHashUntilSufficient(ctx, nil, "request")
	require.NoError(t, err)
	require.NotEmpty(t, hash)
	users, err := ReadUsers(ctx, nil, []string{"one", "two"})
	require.NoError(t, err)
	require.Len(t, users, 2)
	require.True(t, users[0].HasSafe)
}

func TestCoverageOperationValidation(t *testing.T) {
	id := uuid.Must(uuid.NewV4()).String()
	for _, curve := range []uint8{
		CurveSecp256k1ECDSABitcoin,
		CurveSecp256k1ECDSAEthereum,
		CurveSecp256k1SchnorrBitcoin,
		CurveEdwards25519Default,
		CurveEdwards25519Mixin,
		CurveSecp256k1ECDSALitecoin,
		CurveSecp256k1ECDSAMVM,
		CurveSecp256k1ECDSAPolygon,
	} {
		op := &Operation{Id: id, Type: OperationTypeSignInput, Curve: curve, Public: "0102", Extra: []byte("extra")}
		require.Equal(t, uuid.Must(uuid.FromString(id)).Bytes(), op.IdBytes())
		decoded, err := DecodeOperation(op.Encode())
		require.NoError(t, err)
		require.Equal(t, op, decoded)
	}
	require.Panics(t, func() { NormalizeCurve(0) })
	require.Panics(t, func() { (&Operation{Id: id, Curve: 250}).Encode() })
	require.Panics(t, func() { (&Operation{Id: "invalid", Curve: CurveSecp256k1ECDSABitcoin}).Encode() })
	require.Panics(t, func() { (&Operation{Id: id, Curve: CurveSecp256k1ECDSABitcoin, Public: "zz"}).Encode() })
	require.Panics(t, func() { writeBytes(mixincommon.NewEncoder(), make([]byte, 201)) })

	valid := (&Operation{Id: id, Type: 1, Curve: CurveSecp256k1ECDSABitcoin}).Encode()
	for i := 0; i < len(valid); i++ {
		_, err := DecodeOperation(valid[:i])
		require.Error(t, err)
	}
}

func TestCoverageRequestValidation(t *testing.T) {
	ctx := EnableTestEnvironment(context.Background())
	id := uuid.Must(uuid.NewV4()).String()
	assetID := uuid.Must(uuid.NewV4()).String()
	holder := "02a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc"
	hash := mixincrypto.Sha256Hash([]byte("request"))
	createdAt := time.Now().UTC()
	op := &Operation{
		Id:     id,
		Type:   ActionBitcoinSafeProposeAccount,
		Curve:  CurveSecp256k1ECDSABitcoin,
		Public: holder,
		Extra:  []byte{1, 2, 3},
	}
	out := &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{
		OutputId:           uuid.Must(uuid.NewV4()).String(),
		TransactionHash:    hash.String(),
		OutputIndex:        2,
		AssetId:            assetID,
		Amount:             decimal.NewFromInt(1),
		SequencerCreatedAt: createdAt,
		Sequence:           7,
	}}
	req, err := DecodeRequest(out, op.Encode(), RequestRoleHolder)
	require.NoError(t, err)
	require.Equal(t, op.Type, req.Operation().Type)
	require.Equal(t, op.Extra, req.ExtraBytes())
	require.Equal(t, op.Extra, req.Operation().Extra)
	require.False(t, req.Restored)

	_, err = DecodeRequest(out, []byte{1}, RequestRoleHolder)
	require.Error(t, err)
	badOut := *out
	badOut.TransactionHash = "invalid"
	_, err = DecodeRequest(&badOut, op.Encode(), RequestRoleHolder)
	require.Error(t, err)

	valid := *req
	cases := []func(*Request){
		func(r *Request) { r.Action = 0 },
		func(r *Request) { r.AssetId = "invalid" },
		func(r *Request) { r.Amount = decimal.Zero },
		func(r *Request) { r.MixinHash = mixincrypto.Hash{} },
		func(r *Request) { r.Curve = 0xff },
		func(r *Request) { r.Holder = "invalid" },
	}
	for _, mutate := range cases {
		candidate := valid
		mutate(&candidate)
		require.Error(t, candidate.VerifyFormat())
	}
	zeroTime := valid
	zeroTime.CreatedAt = time.Time{}
	require.Panics(t, func() { zeroTime.VerifyFormat() })
	ethereumRequest := valid
	ethereumRequest.Curve = CurveSecp256k1ECDSAEthereum
	require.NoError(t, ethereumRequest.VerifyFormat())

	for state, name := range map[int]string{
		RequestStateInitial: "initial",
		RequestStatePending: "pending",
		RequestStateDone:    "done",
		RequestStateFailed:  "failed",
	} {
		require.Equal(t, name, StateName(state))
	}
	require.Panics(t, func() { StateName(0xff) })

	receiver := uuid.Must(uuid.NewV4())
	extra := []byte{0, 1, 1, 1}
	extra = append(extra, receiver.Bytes()...)
	proposal := &Request{Action: ActionBitcoinSafeProposeAccount, Holder: holder}
	parsed, err := proposal.ParseMixinRecipient(ctx, nil, extra)
	require.NoError(t, err)
	require.Equal(t, []string{receiver.String()}, parsed.Receivers)

	withObserver := append(append([]byte(nil), extra...), DecodeHexOrPanic(holder)...)
	parsed, err = proposal.ParseMixinRecipient(ctx, nil, withObserver)
	require.NoError(t, err)
	require.Equal(t, holder, parsed.Observer)
	proposal.Action = ActionEthereumSafeProposeAccount
	_, err = proposal.ParseMixinRecipient(ctx, nil, withObserver)
	require.NoError(t, err)
	proposal.Action = 0xff
	require.Panics(t, func() { proposal.ParseMixinRecipient(ctx, nil, extra) })

	proposal.Action = ActionBitcoinSafeProposeAccount
	invalidExtras := [][]byte{
		nil,
		{0, 0, 1, 1},
		{0, 1, 0, 1},
		{0, 1, 2, 1},
		append([]byte{0, 1, 1, 1}, receiver.Bytes()[:15]...),
		append(append([]byte(nil), extra...), 1),
		append(append([]byte(nil), extra...), make([]byte, 33)...),
	}
	for _, invalid := range invalidExtras {
		_, err := proposal.ParseMixinRecipient(ctx, nil, invalid)
		require.Error(t, err)
	}
}

func TestCoverageSQLiteAndWalletHelpers(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/properties.sqlite3"
	schema := `CREATE TABLE properties (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);`
	db, err := OpenSQLite3Store(path, schema)
	require.NoError(t, err)
	store := &SQLite3Store{db: db, mutex: new(sync.RWMutex)}
	require.Empty(t, mustReadProperty(t, store, ctx, "missing"))
	require.NoError(t, store.WriteOrUpdateProperty(ctx, "key", "one"))
	require.Equal(t, "one", mustReadProperty(t, store, ctx, "key"))
	require.NoError(t, store.WriteOrUpdateProperty(ctx, "key", "two"))
	require.Equal(t, "two", mustReadProperty(t, store, ctx, "key"))
	require.Equal(t, "INSERT INTO table_name (a,b) VALUES (?, ?)", buildInsertionSQL("table_name", []string{"a", "b"}))

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	exists, err := store.checkExistence(ctx, tx, "SELECT value FROM properties WHERE key=?", "key")
	require.NoError(t, err)
	require.True(t, exists)
	require.Error(t, store.execMultiple(ctx, tx, 2, "UPDATE properties SET value=? WHERE key=?", "three", "key"))
	require.NoError(t, tx.Rollback())
	Rollback(tx)

	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.Error(t, store.execOne(ctx, tx, "not valid sql"))
	Rollback(tx)
	require.NoError(t, store.Close())

	readOnly, err := OpenSQLite3ReadOnlyStore(path)
	require.NoError(t, err)
	var value string
	require.NoError(t, readOnly.QueryRow("SELECT value FROM properties WHERE key='key'").Scan(&value))
	require.Equal(t, "two", value)
	require.NoError(t, readOnly.Close())

	walletStore, err := OpenWalletSQLite3Store(t.TempDir() + "/wallet.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, walletStore.Close()) })
	client := &mixin.Client{ClientID: uuid.Must(uuid.NewV4()).String()}
	wallet := NewMixinWallet(client, walletStore, 100)
	require.Equal(t, uint64(100), mustCheckpoint(t, wallet, ctx))
	require.NoError(t, wallet.writeDrainCheckpoint(ctx, 99))
	require.Equal(t, uint64(100), mustCheckpoint(t, wallet, ctx))
	require.NoError(t, wallet.writeDrainCheckpoint(ctx, 101))
	require.Equal(t, uint64(101), mustCheckpoint(t, wallet, ctx))
	require.NoError(t, walletStore.WriteOrUpdateProperty(ctx, OutputsDrainKey, "invalid"))
	require.Panics(t, func() { _, _ = wallet.readDrainCheckpoint(ctx) })

	utxo := &mixin.SafeUtxo{
		OutputID:         uuid.Must(uuid.NewV4()).String(),
		TransactionHash:  mixinnet.Hash{1},
		OutputIndex:      3,
		KernelAssetID:    mixinnet.Hash{2},
		AssetID:          uuid.Must(uuid.NewV4()).String(),
		Amount:           decimal.RequireFromString("1.25"),
		SendersThreshold: 1,
		Senders:          []string{"sender"},
		State:            mixin.SafeUtxoStateUnspent,
		Sequence:         9,
		CreatedAt:        time.Now().UTC(),
	}
	converted := toBotOutput([]*mixin.SafeUtxo{utxo})
	require.Equal(t, []*bot.Output{{
		OutputID:        utxo.OutputID,
		TransactionHash: utxo.TransactionHash.String(),
		OutputIndex:     uint(utxo.OutputIndex),
		AssetId:         utxo.AssetID,
		KernelAssetId:   utxo.KernelAssetID.String(),
		Amount:          utxo.Amount.String(),
		State:           string(utxo.State),
		Sequence:        int64(utxo.Sequence),
	}}, converted)
}

func TestCoverageUtilityHelpers(t *testing.T) {
	require.Equal(t, []byte("ok"), MarshalPanic(coverageBinaryMarshaler{b: []byte("ok")}))
	require.Panics(t, func() { MarshalPanic(coverageBinaryMarshaler{err: errors.New("marshal")}) })
	require.JSONEq(t, `{"ok":true}`, string(MarshalJSONOrPanic(map[string]bool{"ok": true})))
	require.Panics(t, func() { MarshalJSONOrPanic(make(chan int)) })
	require.Equal(t, []byte{0xab}, DecodeHexOrPanic("ab"))
	require.Panics(t, func() { DecodeHexOrPanic("zz") })
	require.True(t, CheckUnique("a", "b", 1))
	require.False(t, CheckUnique("a", "a"))
	require.True(t, CheckTestEnvironment(EnableTestEnvironment(context.Background())))

	for _, message := range []string{
		"insufficient outputs for transaction",
		"locked by another transaction",
		"locked by other transaction",
		"spent by other transaction",
		"inputs locked by another transaction",
	} {
		require.True(t, CheckTransactionLockedError(errors.New(message)))
		require.True(t, CheckRetryableError(errors.New(message)))
	}
	require.False(t, CheckTransactionLockedError(nil))
	require.False(t, CheckTransactionLockedError(errors.New("permanent")))

	hashes := []mixincrypto.Hash{mixincrypto.Sha256Hash([]byte("one")), mixincrypto.Sha256Hash([]byte("two"))}
	converted := toMixinnetHash(hashes)
	require.Len(t, converted, 2)
	require.Equal(t, hashes[0][:], converted[0][:])
}

func mustReadProperty(t *testing.T, store *SQLite3Store, ctx context.Context, key string) string {
	t.Helper()
	value, err := store.ReadProperty(ctx, key)
	require.NoError(t, err)
	return value
}

func mustCheckpoint(t *testing.T, wallet *MixinWallet, ctx context.Context) uint64 {
	t.Helper()
	checkpoint, err := wallet.readDrainCheckpoint(ctx)
	require.NoError(t, err)
	return checkpoint
}
