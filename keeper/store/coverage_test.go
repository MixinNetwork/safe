package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestCoveragePropertiesRequestsNetworkAndKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t)

	value, err := s.ReadProperty(ctx, "missing")
	require.NoError(t, err)
	require.Empty(t, value)
	require.NoError(t, s.WriteProperty(ctx, "key", "value"))
	value, err = s.ReadProperty(ctx, "key")
	require.NoError(t, err)
	require.Equal(t, "value", value)
	require.Error(t, s.WriteProperty(ctx, "key", "duplicate"))
	terminated, err := s.ReadTerminate(ctx)
	require.NoError(t, err)
	require.False(t, terminated)
	require.NoError(t, s.WriteTerminate(ctx))
	terminated, err = s.ReadTerminate(ctx)
	require.NoError(t, err)
	require.True(t, terminated)
	require.Equal(t, "INSERT INTO sample (a,b) VALUES (?, ?)", buildInsertionSQL("sample", []string{"a", "b"}))

	missing, err := s.ReadRequest(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, missing)
	req := coverageRequest(common.ActionBitcoinSafeProposeAccount)
	require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
	require.NoError(t, s.WriteRequestIfNotExist(ctx, req))
	stored, err := s.ReadRequest(ctx, req.Id)
	require.NoError(t, err)
	require.Equal(t, req.Id, stored.Id)
	pending, err := s.ReadPendingRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, req.Id, pending.Id)
	latest, err := s.ReadLatestRequest(ctx)
	require.NoError(t, err)
	require.Equal(t, req.Id, latest.Id)

	ar, handled, err := s.ReadActionResult(ctx, req.Output.OutputId, req.Id)
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, ar)
	require.NoError(t, s.FailAction(ctx, req))
	ar, handled, err = s.ReadActionResult(ctx, req.Output.OutputId, req.Id)
	require.NoError(t, err)
	require.False(t, handled)
	require.Nil(t, ar)
	require.NoError(t, s.FailRequest(ctx, req, "asset", nil))
	ar, handled, err = s.ReadActionResult(ctx, req.Output.OutputId, req.Id)
	require.NoError(t, err)
	require.True(t, handled)
	require.NotNil(t, ar)
	require.Equal(t, "asset", ar.Compaction)
	require.NoError(t, s.ResetRequest(ctx, req))
	stored, err = s.ReadRequest(ctx, req.Id)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateInitial), stored.State)
	require.Panics(t, func() { s.WriteRequestIfNotExist(ctx, &common.Request{}) })

	networkReq := coverageRequest(common.ActionObserverUpdateNetworkStatus)
	require.NoError(t, s.WriteRequestIfNotExist(ctx, networkReq))
	require.Nil(t, mustNetworkInfo(t, s, ctx, "missing"))
	now := time.Now().UTC()
	info := &NetworkInfo{RequestId: networkReq.Id, Chain: common.SafeChainBitcoin, Fee: 10, Height: 100, Hash: crypto.Sha256Hash([]byte("block")).String(), CreatedAt: now}
	require.NoError(t, s.WriteNetworkInfoFromRequest(ctx, info, networkReq))
	require.Equal(t, info.Hash, mustNetworkInfo(t, s, ctx, info.RequestId).Hash)
	latestInfo, err := s.ReadLatestNetworkInfo(ctx, info.Chain, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, info.RequestId, latestInfo.RequestId)
	latestInfo, err = s.ReadLatestNetworkInfo(ctx, info.Chain, now.Add(-time.Second))
	require.NoError(t, err)
	require.Nil(t, latestInfo)

	paramsReq := coverageRequest(common.ActionObserverSetOperationParams)
	require.NoError(t, s.WriteRequestIfNotExist(ctx, paramsReq))
	params := &OperationParams{
		RequestId:            paramsReq.Id,
		Chain:                common.SafeChainEthereum,
		OperationPriceAsset:  uuid.Must(uuid.NewV4()).String(),
		OperationPriceAmount: decimal.RequireFromString("1.25"),
		TransactionMinimum:   decimal.RequireFromString("0.01"),
		CreatedAt:            now,
	}
	require.NoError(t, s.WriteOperationParamsFromRequest(ctx, params, paramsReq))
	readParams, err := s.ReadLatestOperationParams(ctx, params.Chain, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, params.OperationPriceAmount, readParams.OperationPriceAmount)
	require.NoError(t, s.WriteOperationParamsFromRequest(ctx, params, paramsReq))
	readParams, err = s.ReadLatestOperationParams(ctx, common.SafeChainPolygon, now)
	require.NoError(t, err)
	require.Nil(t, readParams)

	asset := &Asset{
		AssetId: uuid.Must(uuid.NewV4()).String(), MixinId: crypto.Sha256Hash([]byte("mixin-asset")).String(),
		AssetKey: "asset-key", Symbol: "SAFE", Name: "Safe Asset", Decimals: 8, Chain: common.SafeChainBitcoin, CreatedAt: now,
	}
	require.NoError(t, s.WriteAssetMeta(ctx, asset))
	readAsset, err := s.ReadAssetMeta(ctx, asset.AssetId)
	require.NoError(t, err)
	require.Equal(t, asset.Symbol, readAsset.Symbol)
	readAsset, err = s.ReadAssetMeta(ctx, asset.MixinId)
	require.NoError(t, err)
	require.Equal(t, asset.AssetId, readAsset.AssetId)
	readAsset, err = s.ReadAssetMeta(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, readAsset)
	require.Error(t, s.WriteAssetMeta(ctx, asset))

	signerReq := coverageKeyRequest(common.RequestRoleSigner, time.Now().Add(-2*time.Hour))
	observerReq := coverageKeyRequest(common.RequestRoleObserver, time.Now().Add(-2*time.Hour))
	require.NoError(t, s.WriteRequestIfNotExist(ctx, signerReq))
	require.NoError(t, s.WriteRequestIfNotExist(ctx, observerReq))
	require.NoError(t, s.WriteKeyFromRequest(ctx, signerReq, common.RequestRoleSigner, []byte("signer-extra"), common.RequestFlagNone))
	require.NoError(t, s.WriteKeyFromRequest(ctx, observerReq, common.RequestRoleObserver, []byte("observer-extra"), common.RequestFlagNone))
	key, err := s.ReadKey(ctx, signerReq.Holder)
	require.NoError(t, err)
	require.Equal(t, signerReq.Holder, key.Public)
	count, err := s.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleSigner)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	accountReq := coverageRequest(common.ActionBitcoinSafeProposeAccount)
	accountReq.Holder = "account-holder"
	signer, observer, err := s.AssignSignerAndObserverToHolder(ctx, accountReq, time.Hour, "")
	require.NoError(t, err)
	require.Equal(t, signerReq.Holder, signer)
	require.Equal(t, observerReq.Holder, observer)
	signerAgain, observerAgain, err := s.AssignSignerAndObserverToHolder(ctx, accountReq, time.Hour, "")
	require.NoError(t, err)
	require.Equal(t, signer, signerAgain)
	require.Equal(t, observer, observerAgain)

	missingKeysReq := coverageRequest(common.ActionBitcoinSafeProposeAccount)
	missingKeysReq.Holder = "missing-keys-holder"
	missingSigner, missingObserver, err := s.AssignSignerAndObserverToHolder(ctx, missingKeysReq, time.Hour, "")
	require.NoError(t, err)
	require.Empty(t, missingSigner)
	require.Empty(t, missingObserver)

	badCurveReq := coverageKeyRequest(common.RequestRoleSigner, time.Now())
	badCurveReq.Curve = common.CurveSecp256k1ECDSALitecoin
	require.NoError(t, s.WriteRequestIfNotExist(ctx, badCurveReq))
	require.Panics(t, func() { s.WriteKeyFromRequest(ctx, badCurveReq, common.RequestRoleSigner, nil, 0) })
}

func TestCoverageSafesBitcoinAndEthereumDeposits(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t)
	now := time.Now().UTC()

	proposalReq := coverageRequest(common.ActionBitcoinSafeProposeAccount)
	require.NoError(t, s.WriteRequestIfNotExist(ctx, proposalReq))
	proposal := &SafeProposal{
		RequestId: proposalReq.Id, Chain: common.SafeChainBitcoin, Holder: "proposal-holder", Signer: "proposal-signer", Observer: "proposal-observer",
		Timelock: time.Hour, Path: "00000000", Address: "proposal-address", Extra: []byte("extra"), Receivers: []string{"one", "two"}, Threshold: 2,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteSafeProposalWithRequest(ctx, proposal, nil, proposalReq))
	readProposal, err := s.ReadSafeProposal(ctx, proposal.RequestId)
	require.NoError(t, err)
	require.Equal(t, proposal.Receivers, readProposal.Receivers)
	readProposal, err = s.ReadSafeProposalByAddress(ctx, proposal.Address)
	require.NoError(t, err)
	require.Equal(t, proposal.RequestId, readProposal.RequestId)
	readProposal, err = s.ReadSafeProposal(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, readProposal)

	pendingSafe := coverageSafe("pending-holder", "pending-address", common.SafeChainEthereum, common.RequestStatePending)
	require.NoError(t, s.WriteUnfinishedSafe(ctx, pendingSafe))
	require.NoError(t, s.WriteUnfinishedSafe(ctx, pendingSafe))
	require.Panics(t, func() {
		invalid := *pendingSafe
		invalid.Holder = "invalid-state-holder"
		invalid.Address = "invalid-state-address"
		invalid.State = common.RequestStateInitial
		s.WriteUnfinishedSafe(ctx, &invalid)
	})
	readSafe, err := s.ReadSafe(ctx, pendingSafe.Holder)
	require.NoError(t, err)
	require.Equal(t, pendingSafe.Address, readSafe.Address)
	pendingSafes, err := s.ListSafesWithState(ctx, common.RequestStatePending)
	require.NoError(t, err)
	require.Len(t, pendingSafes, 1)

	finishTxReq := coverageRequest(common.ActionEthereumSafeProposeTransaction)
	finishTxReq.Holder = pendingSafe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, finishTxReq))
	finishTx := coverageTransaction(finishTxReq, pendingSafe.Holder, common.SafeChainEthereum)
	require.NoError(t, s.WriteTransactionWithRequest(ctx, finishTx, nil, nil, nil, finishTxReq))
	finishReq := coverageRequest(common.ActionEthereumSafeApproveAccount)
	finishReq.Holder = pendingSafe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, finishReq))
	require.NoError(t, s.FinishSafeWithRequest(ctx, finishTx.TransactionHash, "finished-raw", finishReq, pendingSafe, nil))
	readSafe, err = s.ReadSafe(ctx, pendingSafe.Holder)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateDone), readSafe.State)
	require.Equal(t, int64(1), readSafe.Nonce)

	// The store only needs a witness script whose hash deterministically maps to
	// the safe address; script semantics are exercised in apps/bitcoin tests.
	script := make([]byte, 101)
	bitcoinAddress, err := bitcoin.EncodeAddress(script, common.SafeChainBitcoin)
	require.NoError(t, err)
	bitcoinReq := coverageRequest(common.ActionBitcoinSafeApproveAccount)
	bitcoinSafe := coverageSafe("bitcoin-holder", bitcoinAddress, common.SafeChainBitcoin, common.RequestStateDone)
	bitcoinSafe.RequestId = bitcoinReq.Id
	require.NoError(t, s.WriteRequestIfNotExist(ctx, bitcoinReq))
	require.NoError(t, s.WriteSafeWithRequest(ctx, bitcoinSafe, nil, bitcoinReq))
	readSafe, err = s.ReadSafeByAddress(ctx, bitcoinAddress)
	require.NoError(t, err)
	require.Equal(t, bitcoinSafe.Holder, readSafe.Holder)
	doneSafes, err := s.ListSafesWithState(ctx, common.RequestStateDone)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(doneSafes), 2)
	require.Panics(t, func() {
		invalid := *bitcoinSafe
		invalid.Holder = "invalid-done-holder"
		invalid.Address = "invalid-done-address"
		invalid.RequestId = uuid.Must(uuid.NewV4()).String()
		invalid.State = common.RequestStatePending
		s.WriteSafeWithRequest(ctx, &invalid, nil, &common.Request{Output: &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String()}}})
	})

	depositReq := coverageRequest(common.ActionObserverHolderDeposit)
	depositReq.Holder = bitcoinSafe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, depositReq))
	utxo := &bitcoin.Input{
		TransactionHash: crypto.Sha256Hash([]byte("bitcoin-deposit")).String(), Index: 1, Satoshi: 100_000,
		Script: script, Sequence: 10,
	}
	require.NoError(t, s.WriteBitcoinOutputFromRequest(ctx, bitcoinSafe, utxo, depositReq, common.SafeBitcoinChainId, "sender", nil))
	readUTXO, spentBy, err := s.ReadBitcoinUTXO(ctx, utxo.TransactionHash, int(utxo.Index))
	require.NoError(t, err)
	require.Equal(t, utxo.Satoshi, readUTXO.Satoshi)
	require.Empty(t, spentBy)
	missingUTXO, _, err := s.ReadBitcoinUTXO(ctx, "missing", 0)
	require.NoError(t, err)
	require.Nil(t, missingUTXO)
	allUTXOs, err := s.ListAllBitcoinUTXOsForHolder(ctx, bitcoinSafe.Holder)
	require.NoError(t, err)
	require.Len(t, allUTXOs, 1)
	count, err := s.ReadUnspentUtxoCountForSafe(ctx, bitcoinAddress)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	deposit, err := s.ReadDeposit(ctx, utxo.TransactionHash, int64(utxo.Index))
	require.NoError(t, err)
	require.Equal(t, bitcoinSafe.Holder, deposit.Holder)
	missingDeposit, err := s.ReadDeposit(ctx, "missing", 0)
	require.NoError(t, err)
	require.Nil(t, missingDeposit)
	_, err = s.db.Exec("UPDATE bitcoin_outputs SET state=? WHERE transaction_hash=? AND output_index=?", common.RequestStatePending, utxo.TransactionHash, utxo.Index)
	require.NoError(t, err)
	pendingUTXOs, err := s.ListPendingBitcoinUTXOsForHolder(ctx, bitcoinSafe.Holder)
	require.NoError(t, err)
	require.Len(t, pendingUTXOs, 1)

	ethereumSafe := coverageSafe("ethereum-holder", "0x1111111111111111111111111111111111111111", common.SafeChainEthereum, common.RequestStateDone)
	zero, err := s.ReadEthereumBalance(ctx, ethereumSafe.Address, "asset", "safe-asset")
	require.NoError(t, err)
	require.Zero(t, zero.BigBalance().Sign())
	zero.UpdateBalance(big.NewInt(100))
	zero.AssetAddress = "0x2222222222222222222222222222222222222222"
	ethDepositReq := coverageRequest(common.ActionObserverHolderDeposit)
	ethDepositReq.Holder = ethereumSafe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, ethDepositReq))
	ethHash := "0x" + crypto.Sha256Hash([]byte("ethereum-deposit")).String()
	require.NoError(t, s.CreateEthereumBalanceDepositFromRequest(ctx, ethereumSafe, zero, ethHash, 0, big.NewInt(100), "sender", ethDepositReq, nil))
	readBalance, err := s.ReadEthereumBalance(ctx, ethereumSafe.Address, zero.AssetId, zero.SafeAssetId)
	require.NoError(t, err)
	require.Equal(t, "100", readBalance.BigBalance().String())
	balances, err := s.ReadAllEthereumTokenBalances(ctx, ethereumSafe.Address)
	require.NoError(t, err)
	require.Len(t, balances, 1)
	allMap, err := s.ReadAllEthereumTokenBalancesMap(ctx, ethereumSafe.Address)
	require.NoError(t, err)
	require.Equal(t, readBalance.AssetId, allMap[readBalance.AssetAddress].AssetId)
	positive, err := s.ReadPositiveEthereumTokenBalancesMap(ctx, ethereumSafe.Address)
	require.NoError(t, err)
	require.Len(t, positive, 1)
	require.Panics(t, func() { s.ReadEthereumBalance(ctx, ethereumSafe.Address, zero.AssetId, "wrong-safe-asset") })
	require.Panics(t, func() { (&SafeBalance{balance: "invalid"}).BigBalance() })
	require.Panics(t, func() { (&SafeBalance{balance: "0"}).UpdateBalance(big.NewInt(-1)) })

	readBalance.UpdateBalance(big.NewInt(-100))
	updateReq := coverageRequest(common.ActionObserverHolderDeposit)
	updateReq.Holder = ethereumSafe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, updateReq))
	require.NoError(t, s.CreateEthereumBalanceDepositFromRequest(ctx, ethereumSafe, readBalance, ethHash+"1", 1, big.NewInt(0), "sender", updateReq, nil))
	positive, err = s.ReadPositiveEthereumTokenBalancesMap(ctx, ethereumSafe.Address)
	require.NoError(t, err)
	require.Empty(t, positive)
}

func TestCoverageTransactionsSignaturesAndInheritance(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t)
	now := time.Now().UTC()

	safeReq := coverageRequest(common.ActionEthereumSafeApproveAccount)
	safe := coverageSafe("transaction-holder", "0x3333333333333333333333333333333333333333", common.SafeChainEthereum, common.RequestStateDone)
	safe.RequestId = safeReq.Id
	require.NoError(t, s.WriteRequestIfNotExist(ctx, safeReq))
	require.NoError(t, s.WriteSafeWithRequest(ctx, safe, nil, safeReq))

	txReq := coverageRequest(common.ActionEthereumSafeProposeTransaction)
	txReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, txReq))
	trx := coverageTransaction(txReq, safe.Holder, safe.Chain)
	lock := &InheritanceLock{
		LockId: uuid.Must(uuid.NewV4()).String(), RequestId: txReq.Id, Hash: trx.TransactionHash, Holder: safe.Holder,
		Address: safe.Address, Chain: safe.Chain, Duration: 24 * time.Hour, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteTransactionWithRequest(ctx, trx, nil, lock, nil, txReq))
	readTx, err := s.ReadTransaction(ctx, trx.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, trx.RequestId, readTx.RequestId)
	readTx, err = s.ReadTransactionByRequestId(ctx, trx.RequestId)
	require.NoError(t, err)
	require.Equal(t, trx.TransactionHash, readTx.TransactionHash)
	latestTx, err := s.ReadLatestTransactionByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	require.Equal(t, trx.TransactionHash, latestTx.TransactionHash)
	count, err := s.CountTransactionsByState(ctx, common.RequestStateInitial)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	count, err = s.CountUnfinishedTransactionsByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	unfinished, err := s.ReadUnfinishedTransactionsByHolder(ctx, safe.Holder)
	require.NoError(t, err)
	require.Len(t, unfinished, 1)
	missingTx, err := s.ReadTransaction(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, missingTx)

	readLock, err := s.ReadInheritanceLock(ctx, lock.LockId)
	require.NoError(t, err)
	require.Equal(t, lock.RequestId, readLock.RequestId)
	readLock, err = s.ReadInheritanceLockByRequestId(ctx, lock.RequestId)
	require.NoError(t, err)
	require.Equal(t, lock.LockId, readLock.LockId)
	readLock, err = s.ReadLatestInheritanceLockByHolder(ctx, lock.Holder)
	require.NoError(t, err)
	require.Equal(t, lock.LockId, readLock.LockId)
	locks, err := s.ListInheritanceLocksByHolder(ctx, lock.Holder)
	require.NoError(t, err)
	require.Len(t, locks, 1)
	missingLock, err := s.ReadInheritanceLock(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, missingLock)

	signatureActionReq := coverageRequest(common.ActionEthereumSafeApproveTransaction)
	signatureActionReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, signatureActionReq))
	signature := &SignatureRequest{
		RequestId: uuid.Must(uuid.NewV4()).String(), TransactionHash: trx.TransactionHash, InputIndex: 0, Signer: "signer",
		Curve: common.CurveSecp256k1ECDSAEthereum, Message: "message", State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteSignatureRequestsWithRequest(ctx, []*SignatureRequest{signature}, trx.TransactionHash, "updated-raw", signatureActionReq, nil))
	readSignature, err := s.ReadSignatureRequest(ctx, signature.RequestId)
	require.NoError(t, err)
	require.Equal(t, signature.Message, readSignature.Message)
	readSignature, err = s.ReadPendingSignatureRequestByTransactionIndex(ctx, trx.TransactionHash, 0)
	require.NoError(t, err)
	require.Equal(t, signature.RequestId, readSignature.RequestId)
	initialSignatures, err := s.ListAllSignaturesForTransaction(ctx, trx.TransactionHash, common.RequestStateInitial)
	require.NoError(t, err)
	require.Len(t, initialSignatures, 1)
	missingSignature, err := s.ReadSignatureRequest(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, missingSignature)

	signatureResult := coverageRequest(common.OperationTypeSignOutput)
	signatureResult.Id = signature.RequestId
	signatureResult.ExtraHEX = "abcd"
	signatureResult.CreatedAt = now.Add(time.Second)
	require.NoError(t, s.FinishSignatureRequest(ctx, signatureResult))
	readSignature, err = s.ReadSignatureRequest(ctx, signature.RequestId)
	require.NoError(t, err)
	require.Equal(t, common.RequestStatePending, readSignature.State)
	require.Equal(t, "abcd", readSignature.Signature.String)

	finalReq := coverageRequest(common.OperationTypeSignOutput)
	finalReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, finalReq))
	balance := &SafeBalance{Address: safe.Address, AssetId: "asset", AssetAddress: ethereum.EthereumEmptyAddress, SafeAssetId: "safe-asset", balance: "10", UpdatedAt: now}
	lock.State = common.RequestStateDone
	require.NoError(t, s.FinishTransactionSignaturesWithRequest(ctx, trx, "final-raw", finalReq, 0, safe, map[string]*SafeBalance{"asset": balance}, lock, nil))
	readTx, err = s.ReadTransaction(ctx, trx.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, common.RequestStateDone, readTx.State)
	readSafe, err := s.ReadSafe(ctx, safe.Holder)
	require.NoError(t, err)
	require.Equal(t, int64(1), readSafe.Nonce)
	readLock, err = s.ReadInheritanceLock(ctx, lock.LockId)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateDone), readLock.State)
	doneSignatures, err := s.ListAllSignaturesForTransaction(ctx, trx.TransactionHash, common.RequestStateDone)
	require.NoError(t, err)
	require.Len(t, doneSignatures, 1)

	cancelTxReq := coverageRequest(common.ActionEthereumSafeProposeTransaction)
	cancelTxReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, cancelTxReq))
	cancelTx := coverageTransaction(cancelTxReq, safe.Holder, safe.Chain)
	cancelTx.CancelPrevious = trx
	require.NoError(t, s.WriteTransactionWithRequest(ctx, cancelTx, nil, nil, nil, cancelTxReq))
	cancelFinalReq := coverageRequest(common.OperationTypeSignOutput)
	cancelFinalReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, cancelFinalReq))
	safe.Nonce = 1
	require.NoError(t, s.FinishTransactionSignaturesWithRequest(ctx, cancelTx, "cancel-raw", cancelFinalReq, 0, safe, nil, nil, nil))
	previous, err := s.ReadTransaction(ctx, trx.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, common.RequestStateFailed, previous.State)

	revokeTxReq := coverageRequest(common.ActionEthereumSafeProposeTransaction)
	revokeTxReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, revokeTxReq))
	revokeTx := coverageTransaction(revokeTxReq, safe.Holder, safe.Chain)
	require.NoError(t, s.WriteTransactionWithRequest(ctx, revokeTx, nil, nil, nil, revokeTxReq))
	revokeReq := coverageRequest(common.ActionEthereumSafeRevokeTransaction)
	revokeReq.Holder = safe.Holder
	require.NoError(t, s.WriteRequestIfNotExist(ctx, revokeReq))
	require.NoError(t, s.RevokeTransactionWithRequest(ctx, revokeTx, safe, revokeReq, nil, nil))
	revoked, err := s.ReadTransaction(ctx, revokeTx.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, common.RequestStateFailed, revoked.State)

	require.False(t, transactionHasOutputs(common.SafeChainEthereum))
	require.True(t, transactionHasOutputs(common.SafeChainBitcoin))
	require.False(t, transactionHasBalance(common.SafeChainBitcoin))
	require.True(t, transactionHasBalance(common.SafeChainEthereum))
	require.Panics(t, func() { transactionHasOutputs(0xff) })
	require.Panics(t, func() { transactionHasBalance(0xff) })
	inputs := TransactionInputsFromBitcoin([]*bitcoin.Input{{TransactionHash: "hash", Index: 7}})
	require.Equal(t, uint32(7), inputs[0].Index)
}

func TestCoverageMigrationAndReadOnlyStore(t *testing.T) {
	ctx := context.Background()
	s, path := coverageStore(t)
	now := time.Now().UTC()

	_, err := s.db.Exec(
		"INSERT INTO transactions (transaction_hash,raw_transaction,holder,chain,asset_id,state,data,request_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
		"6a5ccb71871db47550acd5429764d724c0e26e9ef63e214954edce2ee80a7e90", "raw", "migration-holder", common.SafeChainEthereum, "asset", common.RequestStateFailed, "data", uuid.Must(uuid.NewV4()).String(), now, now,
	)
	require.NoError(t, err)
	_, err = s.db.Exec(
		"INSERT INTO safes (holder,chain,signer,observer,timelock,path,address,extra,receivers,threshold,request_id,nonce,state,safe_asset_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		"02cf89b2507b8b3ceac013f675da6cf68f1ac7a3c74de2621d9d4790d67bde43a5", common.SafeChainEthereum, "signer", "observer", int64(time.Hour), "path", "migration-address", []byte{}, "receiver", 1, uuid.Must(uuid.NewV4()).String(), 180, common.RequestStateDone, "migration-safe-asset", now, now,
	)
	require.NoError(t, err)
	_, err = s.db.Exec(
		"INSERT INTO ethereum_balances (address,asset_id,asset_address,safe_asset_id,balance,latest_tx_hash,updated_at) VALUES (?,?,?,?,?,?,?)",
		"0xA82bCC5b1942c3BF74C8eef18E1a6E0d8FAFA4cb", "c94ac88f-4671-3976-b60a-09064f1811e8", ethereum.EthereumEmptyAddress, "b5a91ff6-a78b-3838-9fa5-225636c093d0", "77000000000000000000000", "", now,
	)
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))
	require.NoError(t, s.Migrate(ctx))

	var state, nonce int
	require.NoError(t, s.db.QueryRow("SELECT state FROM transactions WHERE transaction_hash=?", "6a5ccb71871db47550acd5429764d724c0e26e9ef63e214954edce2ee80a7e90").Scan(&state))
	require.Equal(t, common.RequestStateDone, state)
	require.NoError(t, s.db.QueryRow("SELECT nonce FROM safes WHERE holder=?", "02cf89b2507b8b3ceac013f675da6cf68f1ac7a3c74de2621d9d4790d67bde43a5").Scan(&nonce))
	require.Equal(t, 181, nonce)
	var balance string
	require.NoError(t, s.db.QueryRow("SELECT balance FROM ethereum_balances WHERE address=?", "0xA82bCC5b1942c3BF74C8eef18E1a6E0d8FAFA4cb").Scan(&balance))
	require.Equal(t, "74500000000000000000000", balance)

	_, err = s.db.Exec("INSERT INTO migrate_assets (safe_asset_id,chain,address,asset_id) VALUES (?,?,?,?)", "safe-asset", common.SafeChainPolygon, "address", "asset")
	require.NoError(t, err)
	migrated, err := s.CheckMigrateAsset(ctx, "address", "asset")
	require.NoError(t, err)
	require.True(t, migrated)
	migrated, err = s.CheckMigrateAsset(ctx, "address", "missing")
	require.NoError(t, err)
	require.False(t, migrated)

	require.NoError(t, s.Close())
	readOnly, err := OpenSQLite3ReadOnlyStore(path)
	require.NoError(t, err)
	value, err := readOnly.ReadProperty(ctx, "SCHEMA:VERSION:STUCK_TX")
	require.NoError(t, err)
	require.NotEmpty(t, value)
	require.NoError(t, readOnly.Close())
}

func coverageStore(t *testing.T) (*SQLite3Store, string) {
	t.Helper()
	path := t.TempDir() + "/keeper.sqlite3"
	s, err := OpenSQLite3Store(path)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := s.Close(); err != nil && err != sql.ErrConnDone {
			// Some tests close the store before reopening it read-only.
			if err.Error() != "sql: database is closed" {
				t.Errorf("close store: %v", err)
			}
		}
	})
	return s, path
}

func coverageRequest(action byte) *common.Request {
	id := uuid.Must(uuid.NewV4()).String()
	now := time.Now().UTC()
	return &common.Request{
		Id: id, MixinHash: crypto.Sha256Hash([]byte(id)), MixinIndex: 0, AssetId: uuid.Must(uuid.NewV4()).String(),
		Amount: decimal.NewFromInt(1), Role: common.RequestRoleHolder, Action: action, Curve: common.CurveSecp256k1ECDSABitcoin,
		Holder: "holder-" + id, ExtraHEX: "00", State: common.RequestStateInitial, CreatedAt: now, Sequence: uint64(now.UnixNano()),
		Output: &mtg.Action{UnifiedOutput: mtg.UnifiedOutput{OutputId: uuid.Must(uuid.NewV4()).String()}},
	}
}

func coverageKeyRequest(role byte, createdAt time.Time) *common.Request {
	req := coverageRequest(common.OperationTypeKeygenOutput)
	req.Role = role
	holder := crypto.Sha256Hash([]byte(req.Id))
	req.Holder = hex.EncodeToString(holder[:])
	req.CreatedAt = createdAt
	return req
}

func coverageSafe(holder, address string, chain byte, state byte) *Safe {
	now := time.Now().UTC()
	return &Safe{
		Holder: holder, Chain: chain, Signer: holder + "-signer", Observer: holder + "-observer", Timelock: time.Hour,
		Path: "00000000", Address: address, Extra: []byte("extra"), Receivers: []string{"receiver"}, Threshold: 1,
		RequestId: uuid.Must(uuid.NewV4()).String(), Nonce: 0, State: state, SafeAssetId: holder + "-safe-asset", CreatedAt: now, UpdatedAt: now,
	}
}

func coverageTransaction(req *common.Request, holder string, chain byte) *Transaction {
	now := time.Now().UTC()
	return &Transaction{
		TransactionHash: crypto.Sha256Hash([]byte(req.Id + holder)).String(), RawTransaction: "00", Holder: holder, Chain: chain,
		AssetId: req.AssetId, State: common.RequestStateInitial, Data: "[]", RequestId: req.Id, CreatedAt: now, UpdatedAt: now,
	}
}

func mustNetworkInfo(t *testing.T, s *SQLite3Store, ctx context.Context, id string) *NetworkInfo {
	t.Helper()
	info, err := s.ReadNetworkInfo(ctx, id)
	require.NoError(t, err)
	return info
}
