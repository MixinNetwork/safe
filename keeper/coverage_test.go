package keeper

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/pelletier/go-toml"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

const coverageKeeperPublicKey = "02a99c2e0e2b1da4d648755ef19bd95139acbbe6564cfb06dec7cd34931ca72cdc"

func TestCoverageKeeperRequestParsing(t *testing.T) {
	node, closeNode := coverageKeeperNode(t)
	defer closeNode()

	holder := coverageKeeperOutput(node, uuid.Must(uuid.NewV4()).String(), common.ActionBitcoinSafeProposeAccount, common.CurveSecp256k1ECDSABitcoin, []byte{common.FlagProposeNormalTransaction, 1}, "holder")
	req, err := node.parseRequest(holder)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestRoleHolder), req.Role)
	require.Equal(t, holder.AssetId, req.AssetId)

	observer := coverageKeeperOutput(node, uuid.Must(uuid.NewV4()).String(), common.ActionBitcoinSafeApproveAccount, common.CurveSecp256k1ECDSABitcoin, []byte{1}, "observer")
	req, err = node.parseRequest(observer)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestRoleObserver), req.Role)

	signer := coverageKeeperOutput(node, uuid.Must(uuid.NewV4()).String(), common.OperationTypeSignOutput, common.CurveSecp256k1ECDSABitcoin, []byte{1}, "signer")
	req, err = node.parseRequest(signer)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestRoleSigner), req.Role)

	tooSmall := *signer
	tooSmall.Amount = decimal.RequireFromString("0.9")
	require.Panics(t, func() { node.parseRequest(&tooSmall) })
	tooSmall = *observer
	tooSmall.Amount = decimal.RequireFromString("0.9")
	require.Panics(t, func() { node.parseRequest(&tooSmall) })

	badObserver := *observer
	badObserver.Senders = []string{"untrusted"}
	_, err = node.parseObserverRequest(&badObserver)
	require.Error(t, err)
	badObserver = *observer
	badObserver.Extra = coverageKeeperWrappedExtra(node.conf.AppId, []byte("short"))
	_, err = node.parseObserverRequest(&badObserver)
	require.Error(t, err)
	badObserver = *observer
	badObserver.Extra = coverageKeeperWrappedExtra(uuid.Must(uuid.NewV4()).String(), []byte("long enough encrypted payload"))
	require.Panics(t, func() { node.parseObserverRequest(&badObserver) })

	badSigner := *signer
	badSigner.SendersThreshold++
	_, err = node.parseSignerResponse(&badSigner)
	require.Error(t, err)
	badSigner = *signer
	badSigner.Senders = append([]string(nil), signer.Senders...)
	badSigner.Senders[0] = uuid.Must(uuid.NewV4()).String()
	_, err = node.parseSignerResponse(&badSigner)
	require.Error(t, err)
	badSigner = *signer
	badSigner.Extra = coverageKeeperWrappedExtra(node.conf.AppId, []byte("short"))
	_, err = node.parseSignerResponse(&badSigner)
	require.Error(t, err)
	badSigner = *signer
	badSigner.Extra = coverageKeeperWrappedExtra(uuid.Must(uuid.NewV4()).String(), []byte("long enough encrypted payload"))
	require.Panics(t, func() { node.parseSignerResponse(&badSigner) })

	badHolder := *holder
	badHolder.Extra = coverageKeeperWrappedExtra(uuid.Must(uuid.NewV4()).String(), []byte("payload"))
	require.Panics(t, func() { node.parseHolderRequest(&badHolder) })
	badHolder = *holder
	badHolder.Extra = coverageKeeperWrappedExtra(node.conf.AppId, nil)
	_, err = node.parseHolderRequest(&badHolder)
	require.Error(t, err)
}

func TestCoverageKeeperRolesLifecycleAndStoreHelpers(t *testing.T) {
	node, closeNode := coverageKeeperNode(t)
	defer closeNode()
	ctx := common.EnableTestEnvironment(context.Background())

	roleCases := map[byte]byte{
		common.OperationTypeKeygenOutput:                   common.RequestRoleSigner,
		common.OperationTypeSignOutput:                     common.RequestRoleSigner,
		common.ActionTerminate:                             common.RequestRoleObserver,
		common.ActionObserverAddKey:                        common.RequestRoleObserver,
		common.ActionObserverRequestSignerKeys:             common.RequestRoleObserver,
		common.ActionObserverUpdateNetworkStatus:           common.RequestRoleObserver,
		common.ActionObserverHolderDeposit:                 common.RequestRoleObserver,
		common.ActionObserverSetOperationParams:            common.RequestRoleObserver,
		common.ActionMigrateSafeToken:                      common.RequestRoleHolder,
		common.ActionBitcoinSafeProposeAccount:             common.RequestRoleHolder,
		common.ActionEthereumSafeProposeAccount:            common.RequestRoleHolder,
		common.ActionBitcoinSafeApproveAccount:             common.RequestRoleObserver,
		common.ActionEthereumSafeApproveAccount:            common.RequestRoleObserver,
		common.ActionBitcoinSafeProposeTransaction:         common.RequestRoleHolder,
		common.ActionEthereumSafeProposeTransaction:        common.RequestRoleHolder,
		common.ActionBitcoinSafeApproveTransaction:         common.RequestRoleObserver,
		common.ActionEthereumSafeApproveTransaction:        common.RequestRoleObserver,
		common.ActionBitcoinSafeRevokeTransaction:          common.RequestRoleObserver,
		common.ActionEthereumSafeRevokeTransaction:         common.RequestRoleObserver,
		common.ActionBitcoinSafeCloseAccount:               common.RequestRoleObserver,
		common.ActionBitcoinSafeCloseAccountByInheritance:  common.RequestRoleObserver,
		common.ActionEthereumSafeCloseAccount:              common.RequestRoleObserver,
		common.ActionEthereumSafeCloseAccountByInheritance: common.RequestRoleObserver,
	}
	for action, role := range roleCases {
		require.Equal(t, role, node.getActionRole(action), "action %d", action)
	}
	require.Zero(t, node.getActionRole(0xff))

	require.Equal(t, 0, node.Index())
	badConfig := *node.conf
	badMTG := *node.conf.MTG
	badConfig.MTG = &badMTG
	badConfig.MTG.App.AppId = uuid.Must(uuid.NewV4()).String()
	badNode := *node
	badNode.conf = &badConfig
	require.Panics(t, func() { badNode.Index() })

	signers := node.GetSigners()
	require.True(t, sort.StringsAreSorted(signers))
	if len(signers) > 0 {
		signers[0] = "mutated"
		require.NotEqual(t, signers, node.GetSigners())
	}
	require.Equal(t, node.conf.MTG.Genesis.Epoch, mustKeeperTimestamp(t, node, ctx))

	out := coverageKeeperOutput(node, uuid.Must(uuid.NewV4()).String(), common.ActionBitcoinSafeProposeTransaction, common.CurveSecp256k1ECDSABitcoin, []byte{common.FlagProposeCancelTransaction, 9}, "holder")
	req, err := node.parseHolderRequest(out)
	require.NoError(t, err)
	require.NoError(t, node.store.WriteRequestIfNotExist(ctx, req))
	require.Equal(t, req.Sequence, mustKeeperTimestamp(t, node, ctx))
	flag, extra := node.getTransactionFlagAndExtra(ctx, req.Id)
	require.Equal(t, byte(common.FlagProposeCancelTransaction), flag)
	require.Equal(t, []byte{9}, extra)

	ref := crypto.Sha256Hash([]byte("storage"))
	storagePayload := []byte("stored observer payload")
	require.NoError(t, node.store.WriteProperty(ctx, ref.String(), base64.RawURLEncoding.EncodeToString(storagePayload)))
	require.Equal(t, storagePayload, node.readStorageExtraFromObserver(ctx, ref))

	require.False(t, node.verifyKernelTransaction(ctx, out))
	out.DepositHash = sqlNullString("deposit")
	require.True(t, node.verifyKernelTransaction(context.Background(), out))
	out.DepositHash = sqlNullString("")
	require.False(t, node.verifyKernelTransaction(context.Background(), out))
	handled, err := node.handleBondAsset(ctx, out)
	require.NoError(t, err)
	require.False(t, handled)

	require.Equal(t, node.conf.PolygonKeeperDepositEntry, node.fetchBondAssetReceiver(ctx, "address", out.AssetId))
	txs, compaction := node.failRequest(ctx, req, "asset-for-compaction")
	require.Nil(t, txs)
	require.Equal(t, "asset-for-compaction", compaction)
	failed, err := node.store.ReadRequest(ctx, req.Id)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateFailed), failed.State)

	require.Panics(t, func() { node.Boot(ctx) })
	require.Panics(t, func() { node.Terminate(ctx) })
	terminated, err := node.store.ReadTerminate(ctx)
	require.NoError(t, err)
	require.True(t, terminated)
}

func TestCoverageKeeperDepositAndNetworkParsing(t *testing.T) {
	node, closeNode := coverageKeeperNode(t)
	defer closeNode()

	asset := uuid.Must(uuid.NewV4())
	hash := crypto.Sha256Hash([]byte("deposit"))
	bitcoinExtra := []byte{common.SafeChainBitcoin}
	bitcoinExtra = append(bitcoinExtra, asset.Bytes()...)
	bitcoinExtra = append(bitcoinExtra, hash[:]...)
	index := make([]byte, 8)
	binary.BigEndian.PutUint64(index, 7)
	bitcoinExtra = append(bitcoinExtra, index...)
	bitcoinExtra = append(bitcoinExtra, big.NewInt(123456789).Bytes()...)
	req := &common.Request{Id: uuid.Must(uuid.NewV4()).String(), Curve: common.CurveSecp256k1ECDSABitcoin, ExtraHEX: hex.EncodeToString(bitcoinExtra)}
	deposit, err := parseDepositExtra(req)
	require.NoError(t, err)
	require.Equal(t, byte(common.SafeChainBitcoin), deposit.Chain)
	require.Equal(t, asset.String(), deposit.Asset)
	require.Equal(t, hash.String(), deposit.Hash)
	require.Equal(t, uint64(7), deposit.Index)
	require.Equal(t, "123456789", deposit.Amount.String())

	ethereumExtra := []byte{common.SafeChainPolygon}
	ethereumExtra = append(ethereumExtra, asset.Bytes()...)
	ethereumExtra = append(ethereumExtra, hash[:]...)
	ethereumExtra = append(ethereumExtra, make([]byte, 19)...)
	ethereumExtra = append(ethereumExtra, 1)
	ethereumExtra = append(ethereumExtra, index...)
	ethereumExtra = append(ethereumExtra, big.NewInt(999).Bytes()...)
	req.Curve = common.CurveSecp256k1ECDSAPolygon
	req.ExtraHEX = hex.EncodeToString(ethereumExtra)
	deposit, err = parseDepositExtra(req)
	require.NoError(t, err)
	require.Equal(t, byte(common.SafeChainPolygon), deposit.Chain)
	require.Equal(t, "0x0000000000000000000000000000000000000001", deposit.AssetAddress)
	require.Equal(t, "0x"+hash.String(), deposit.Hash)
	require.Equal(t, "999", deposit.Amount.String())

	req.ExtraHEX = "00"
	_, err = parseDepositExtra(req)
	require.Error(t, err)
	req.Curve = common.CurveSecp256k1ECDSAEthereum
	req.ExtraHEX = hex.EncodeToString(ethereumExtra)
	require.Panics(t, func() { parseDepositExtra(req) })
	huge := append([]byte(nil), bitcoinExtra[:57]...)
	huge = append(huge, 0x80, 0, 0, 0, 0, 0, 0, 0, 0)
	req.Curve = common.CurveSecp256k1ECDSABitcoin
	req.ExtraHEX = hex.EncodeToString(huge)
	_, err = parseDepositExtra(req)
	require.ErrorContains(t, err, "invalid deposit amount")

	btcRPC, btcAsset := node.bitcoinParams(common.SafeChainBitcoin)
	require.Equal(t, node.conf.BitcoinRPC, btcRPC)
	require.Equal(t, common.SafeBitcoinChainId, btcAsset)
	ltcRPC, ltcAsset := node.bitcoinParams(common.SafeChainLitecoin)
	require.Equal(t, node.conf.LitecoinRPC, ltcRPC)
	require.Equal(t, common.SafeLitecoinChainId, ltcAsset)
	require.Panics(t, func() { node.bitcoinParams(0xff) })
	ethRPC, ethAsset := node.ethereumParams(common.SafeChainEthereum)
	require.Equal(t, node.conf.EthereumRPC, ethRPC)
	require.Equal(t, common.SafeEthereumChainId, ethAsset)
	polygonRPC, polygonAsset := node.ethereumParams(common.SafeChainPolygon)
	require.Equal(t, node.conf.PolygonRPC, polygonRPC)
	require.Equal(t, common.SafePolygonChainId, polygonAsset)
	require.Panics(t, func() { node.ethereumParams(0xff) })

	badFork := &store.NetworkInfo{Chain: common.SafeChainLitecoin, Hash: "579ae05733b2ce28843a75ca39e6d5c6b5e95e7366f927381871fd34e36fb088"}
	valid, err := node.verifyBitcoinNetworkInfo(badFork, nil)
	require.NoError(t, err)
	require.True(t, valid)
	info := &store.NetworkInfo{Chain: common.SafeChainBitcoin, Hash: hash.String(), Height: 10, Fee: 10}
	valid, err = node.verifyBitcoinNetworkInfo(info, &store.NetworkInfo{Hash: info.Hash, Height: info.Height})
	require.NoError(t, err)
	require.True(t, valid)
	info.Fee = 0
	valid, err = node.verifyBitcoinNetworkInfo(info, &store.NetworkInfo{Hash: info.Hash, Height: info.Height})
	require.NoError(t, err)
	require.False(t, valid)
	info.Fee = 10
	_, err = node.verifyBitcoinNetworkInfo(info, &store.NetworkInfo{Hash: info.Hash, Height: info.Height + 1})
	require.Error(t, err)
	info.Hash = "short"
	valid, err = node.verifyBitcoinNetworkInfo(info, nil)
	require.NoError(t, err)
	require.False(t, valid)

	ethInfo := &store.NetworkInfo{Chain: common.SafeChainEthereum, Hash: "0x" + hash.String(), Height: 10}
	valid, err = node.verifyEthereumNetworkInfo(ethInfo, &store.NetworkInfo{Hash: ethInfo.Hash, Height: ethInfo.Height})
	require.NoError(t, err)
	require.True(t, valid)
	_, err = node.verifyEthereumNetworkInfo(ethInfo, &store.NetworkInfo{Hash: ethInfo.Hash, Height: ethInfo.Height + 1})
	require.Error(t, err)
	ethInfo.Hash = "short"
	valid, err = node.verifyEthereumNetworkInfo(ethInfo, nil)
	require.NoError(t, err)
	require.False(t, valid)
}

func TestCoverageKeeperOperationParamsRemainIsolatedByChain(t *testing.T) {
	node, closeNode := coverageKeeperNode(t)
	defer closeNode()
	ctx := common.EnableTestEnvironment(context.Background())

	tests := []struct {
		name          string
		chain         byte
		curve         byte
		asset         string
		encodedPrice  uint64
		expectedPrice string
	}{
		{name: "bitcoin", chain: common.SafeChainBitcoin, curve: common.CurveSecp256k1ECDSABitcoin, asset: common.SafeBitcoinChainId, encodedPrice: 10_000, expectedPrice: "0.0001"},
		{name: "litecoin", chain: common.SafeChainLitecoin, curve: common.CurveSecp256k1ECDSALitecoin, asset: common.SafeLitecoinChainId, encodedPrice: 10_000_000, expectedPrice: "0.1"},
		{name: "ethereum", chain: common.SafeChainEthereum, curve: common.CurveSecp256k1ECDSAEthereum, asset: common.SafeEthereumChainId, encodedPrice: 100_000, expectedPrice: "0.001"},
		{name: "polygon", chain: common.SafeChainPolygon, curve: common.CurveSecp256k1ECDSAPolygon, asset: common.SafePolygonChainId, encodedPrice: 1_000_000_000, expectedPrice: "10"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id := uuid.Must(uuid.NewV4()).String()
			extra := []byte{test.chain}
			extra = append(extra, uuid.Must(uuid.FromString(test.asset)).Bytes()...)
			extra = binary.BigEndian.AppendUint64(extra, test.encodedPrice)
			extra = binary.BigEndian.AppendUint64(extra, 10_000)
			out := coverageKeeperOutput(node, id, common.ActionObserverSetOperationParams, test.curve, extra, "observer")
			req, err := node.parseRequest(out)
			require.NoError(t, err)
			require.NoError(t, node.store.WriteRequestIfNotExist(ctx, req))

			txs, compaction := node.writeOperationParams(ctx, req)
			require.Nil(t, txs)
			require.Empty(t, compaction)
			params, err := node.store.ReadLatestOperationParams(ctx, test.chain, time.Now().Add(time.Second))
			require.NoError(t, err)
			require.NotNil(t, params)
			require.Equal(t, id, params.RequestId)
			require.Equal(t, test.chain, params.Chain)
			require.Equal(t, test.asset, params.OperationPriceAsset)
			require.Equal(t, test.expectedPrice, params.OperationPriceAmount.String())
			require.Equal(t, "0.0001", params.TransactionMinimum.String())
		})
	}
}

func coverageKeeperNode(t *testing.T) (*Node, func()) {
	t.Helper()
	b, err := os.ReadFile("../config/example.toml")
	require.NoError(t, err)
	var conf struct {
		Keeper *Configuration `toml:"keeper"`
		Signer struct {
			MTG *mtg.Configuration `toml:"mtg"`
		} `toml:"signer"`
	}
	require.NoError(t, toml.Unmarshal(b, &conf))
	path := t.TempDir() + "/keeper.sqlite3"
	db, err := OpenSQLite3Store(path)
	require.NoError(t, err)
	node := NewNode(db, nil, conf.Keeper, conf.Signer.MTG, nil)
	return node, func() {
		require.NoError(t, db.Close())
		readOnly, err := OpenSQLite3ReadOnlyStore(path)
		require.NoError(t, err)
		require.NoError(t, readOnly.Close())
	}
}

func coverageKeeperOutput(node *Node, id string, action, curve byte, extra []byte, role string) *mtg.Action {
	op := &common.Operation{Id: id, Type: action, Curve: curve, Public: coverageKeeperPublicKey, Extra: extra}
	payload := op.Encode()
	assetID := uuid.Must(uuid.NewV4()).String()
	senders := []string{"holder"}
	sendersThreshold := int64(1)
	switch role {
	case "observer":
		payload = common.AESEncrypt(node.observerAESKey[:], payload, id)
		assetID = node.conf.ObserverAssetId
		senders = []string{node.conf.ObserverUserId}
	case "signer":
		payload = common.AESEncrypt(node.signerAESKey[:], payload, id)
		assetID = node.conf.AssetId
		senders = node.GetSigners()
		sendersThreshold = int64(node.signer.Genesis.Threshold)
	}
	hash := crypto.Sha256Hash([]byte(id))
	return &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{
		OutputId:           uuid.Must(uuid.NewV4()).String(),
		TransactionHash:    hash.String(),
		OutputIndex:        0,
		AssetId:            assetID,
		Amount:             decimal.NewFromInt(1),
		Senders:            senders,
		SendersThreshold:   sendersThreshold,
		Extra:              coverageKeeperWrappedExtra(node.conf.AppId, payload),
		State:              mtg.SafeUtxoStateUnspent,
		Sequence:           uint64(time.Now().Unix()),
		SequencerCreatedAt: time.Now().UTC(),
	}}
}

func coverageKeeperWrappedExtra(appID string, payload []byte) string {
	return hex.EncodeToString([]byte(mtg.EncodeMixinExtraBase64(appID, payload)))
}

func mustKeeperTimestamp(t *testing.T, node *Node, ctx context.Context) uint64 {
	t.Helper()
	timestamp, err := node.timestamp(ctx)
	require.NoError(t, err)
	return timestamp
}

func sqlNullString(value string) sql.NullString {
	return sql.NullString{Valid: value != "", String: value}
}
