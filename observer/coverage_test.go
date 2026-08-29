package observer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	keeperstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	mixin "github.com/fox-one/mixin-sdk-go/v3"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/require"
)

func TestCoverageObserverPropertiesAccountsAssetsCachesAndStats(t *testing.T) {
	ctx := context.Background()
	s := coverageObserverStore(t)

	value, err := s.ReadProperty(ctx, "missing")
	require.NoError(t, err)
	require.Empty(t, value)
	require.NoError(t, s.WriteProperty(ctx, "property", "one"))
	require.NoError(t, s.WriteProperty(ctx, "property", "two"))
	value, err = s.ReadProperty(ctx, "property")
	require.NoError(t, err)
	require.Equal(t, "two", value)
	require.Equal(t, "INSERT INTO example (a,b) VALUES (?, ?)", buildInsertionSQL("example", []string{"a", "b"}))

	account, err := s.ReadAccount(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, account)
	proposed, err := s.CheckAccountProposed(ctx, "missing")
	require.NoError(t, err)
	require.False(t, proposed)
	require.Error(t, s.SaveAccountApprovalSignature(ctx, "missing", "signature"))
	require.Error(t, s.MarkAccountApproved(ctx, "missing"))
	require.Error(t, s.MarkAccountDeployed(ctx, "missing"))

	createdAt := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, s.WriteAccountProposalIfNotExists(ctx, "account", createdAt))
	require.NoError(t, s.WriteAccountProposalIfNotExists(ctx, "account", createdAt))
	proposed, err = s.CheckAccountProposed(ctx, "account")
	require.NoError(t, err)
	require.True(t, proposed)
	require.NoError(t, s.SaveAccountApprovalSignature(ctx, "account", "signature"))
	require.NoError(t, s.SaveAccountApprovalSignature(ctx, "account", "ignored"))
	accounts, err := s.ListProposedAccountsWithSig(ctx)
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, "signature", accounts[0].Signature.String)
	require.NoError(t, s.MarkAccountApproved(ctx, "account"))
	require.NoError(t, s.MarkAccountDeployed(ctx, "account"))
	require.NoError(t, s.MarkAccountDeployed(ctx, "account"))
	account, err = s.ReadAccount(ctx, "account")
	require.NoError(t, err)
	require.True(t, account.ApprovedAt.Valid)
	require.True(t, account.DeployedAt.Valid)
	accounts, err = s.ListProposedAccountsWithSig(ctx)
	require.NoError(t, err)
	require.Empty(t, accounts)

	asset := &Asset{
		AssetId: uuid.Must(uuid.NewV4()).String(), MixinId: crypto.Sha256Hash([]byte("observer-asset")).String(),
		AssetKey: "asset-key", Symbol: "SAFE", Name: "Safe", Decimals: 8, Chain: common.SafeChainBitcoin, CreatedAt: createdAt,
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

	value, err = s.ReadCache(ctx, "missing", time.Hour)
	require.NoError(t, err)
	require.Empty(t, value)
	require.NoError(t, s.WriteCache(ctx, "cache", "one"))
	require.NoError(t, s.WriteCache(ctx, "cache", "two"))
	value, err = s.ReadCache(ctx, "cache", time.Hour)
	require.NoError(t, err)
	require.Equal(t, "two", value)
	_, err = s.db.Exec("UPDATE caches SET created_at=? WHERE key=?", time.Now().Add(-2*time.Hour), "cache")
	require.NoError(t, err)
	value, err = s.ReadCache(ctx, "cache", time.Hour)
	require.NoError(t, err)
	require.Empty(t, value)

	stats := (&StatsInfo{Type: NodeTypeKeeper, Runtime: "1h", Group: "group"}).String()
	require.NoError(t, s.UpsertNodeStats(ctx, "app", NodeTypeKeeper, stats))
	require.NoError(t, s.UpsertNodeStats(ctx, "app", NodeTypeKeeper, stats))
	nodes, err := s.ListNodeStats(ctx, NodeTypeKeeper)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	parsed, err := nodes[0].getStats()
	require.NoError(t, err)
	require.Equal(t, "1h", parsed.Runtime)
	_, err = (&NodeStats{Stats: "{"}).getStats()
	require.Error(t, err)
}

func TestCoverageObserverDepositsAndTransactions(t *testing.T) {
	ctx := context.Background()
	s := coverageObserverStore(t)
	now := time.Now().UTC().Add(-time.Minute)

	deposit := &Deposit{
		TransactionHash: crypto.Sha256Hash([]byte("deposit")).String(), OutputIndex: 1,
		AssetId: uuid.Must(uuid.NewV4()).String(), AssetAddress: "asset-address", Amount: "1.25",
		Receiver: "receiver", Sender: "sender", State: common.RequestStateInitial, Chain: common.SafeChainBitcoin,
		Holder: "holder", Category: common.ActionObserverHolderDeposit, RequestId: uuid.Must(uuid.NewV4()).String(), CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WritePendingDepositIfNotExists(ctx, deposit))
	require.NoError(t, s.WritePendingDepositIfNotExists(ctx, deposit))
	require.Panics(t, func() {
		invalid := *deposit
		invalid.TransactionHash = crypto.Sha256Hash([]byte("invalid-deposit")).String()
		invalid.State = common.RequestStateDone
		s.WritePendingDepositIfNotExists(ctx, &invalid)
	})

	deposits, err := s.ListDeposits(ctx, int(deposit.Chain), "", 0, 0)
	require.NoError(t, err)
	require.Len(t, deposits, 1)
	deposits, err = s.ListDeposits(ctx, int(deposit.Chain), deposit.Holder, common.RequestStateInitial, 0)
	require.NoError(t, err)
	require.Len(t, deposits, 1)
	unconfirmed, err := s.CheckUnconfirmedDepositsForAssetAndHolder(ctx, deposit.Holder, deposit.AssetId, time.Now())
	require.NoError(t, err)
	require.True(t, unconfirmed)
	unconfirmed, err = s.CheckUnconfirmedDepositsForAssetAndHolder(ctx, deposit.Holder, deposit.AssetId, now.Add(-time.Hour))
	require.NoError(t, err)
	require.False(t, unconfirmed)

	newRequestID := uuid.Must(uuid.NewV4()).String()
	require.NoError(t, s.UpdateDepositRequestId(ctx, deposit.TransactionHash, deposit.OutputIndex, deposit.RequestId, newRequestID))
	require.NoError(t, s.ConfirmPendingDeposit(ctx, deposit.TransactionHash, deposit.OutputIndex, newRequestID))
	deposits, err = s.ListDeposits(ctx, int(deposit.Chain), deposit.Holder, common.RequestStateDone, 0)
	require.NoError(t, err)
	require.Len(t, deposits, 1)
	require.Error(t, s.ConfirmPendingDeposit(ctx, deposit.TransactionHash, deposit.OutputIndex, newRequestID))

	sent := coverageObserverTransaction("sent", common.RequestStateDone, common.SafeChainBitcoin, now)
	sent.SpentHash = sql.NullString{Valid: true, String: deposit.TransactionHash}
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, sent))
	sentHashes, err := s.QueryDepositSentHashes(ctx, deposits)
	require.NoError(t, err)
	require.Equal(t, sent.TransactionHash, sentHashes[deposit.TransactionHash])

	tx := coverageObserverTransaction("approval", common.RequestStateInitial, common.SafeChainEthereum, now)
	missing, err := s.ReadTransactionApproval(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, missing)
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, tx))
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, tx))
	count, err := s.CountUnfinishedTransactionApprovalsForHolder(ctx, tx.Holder)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.NoError(t, s.AddTransactionPartials(ctx, tx.TransactionHash, "partial"))
	readTx, err := s.ReadTransactionApproval(ctx, tx.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "partial", readTx.RawTransaction)
	require.NoError(t, s.MarkTransactionApprovalPaid(ctx, tx.TransactionHash))
	require.NoError(t, s.UpdateTransactionApprovalRequestTime(ctx, tx.TransactionHash))
	pending, err := s.ListPendingTransactionApprovals(ctx, tx.Chain)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, s.FinishTransactionSignatures(ctx, tx.TransactionHash, "fully-signed"))
	fullySigned, err := s.ListFullySignedTransactionApprovals(ctx, tx.Chain)
	require.NoError(t, err)
	require.Len(t, fullySigned, 1)
	require.NoError(t, s.ConfirmFullySignedTransactionApproval(ctx, tx.TransactionHash, "spent-hash", "spent-raw", ""))
	readTx, err = s.ReadTransactionApproval(ctx, "spent-hash")
	require.NoError(t, err)
	require.Equal(t, tx.TransactionHash, readTx.TransactionHash)

	revoked := coverageObserverTransaction("revoked", common.RequestStateInitial, common.SafeChainEthereum, now)
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, revoked))
	require.NoError(t, s.RevokeTransactionApproval(ctx, revoked.TransactionHash, "revoke-signature"))
	readTx, err = s.ReadTransactionApproval(ctx, revoked.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateFailed), readTx.State)
	require.Error(t, s.FinishTransactionSignatures(ctx, revoked.TransactionHash, "late-signatures"))
	readTx, err = s.ReadTransactionApproval(ctx, revoked.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateFailed), readTx.State)
	require.Equal(t, "revoke-signature", readTx.RawTransaction)
	require.Error(t, s.AddTransactionPartials(ctx, "missing", "raw"))
	require.Error(t, s.MarkTransactionApprovalPaid(ctx, "missing"))
	require.Error(t, s.UpdateTransactionApprovalRequestTime(ctx, "missing"))
}

func TestCoverageObserverRecoveriesKeysAndBitcoinOutputs(t *testing.T) {
	ctx := context.Background()
	s := coverageObserverStore(t)
	now := time.Now().UTC()

	recovery := &Recovery{
		Address: "recovery-address", Chain: common.SafeChainEthereum, Holder: "holder", Observer: "observer", RawTransaction: "raw",
		TransactionHash: crypto.Sha256Hash([]byte("recovery")).String(), State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	readRecovery, err := s.ReadRecoveryByHash(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, readRecovery)
	require.NoError(t, s.WriteInitialRecovery(ctx, recovery))
	readRecovery, err = s.ReadRecovery(ctx, recovery.Address, recovery.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "initial", readRecovery.getState())
	require.Panics(t, func() { _, _ = s.ReadRecovery(ctx, "wrong-address", recovery.TransactionHash) })
	recoveries, err := s.ListInitialRecoveries(ctx, 0)
	require.NoError(t, err)
	require.Len(t, recoveries, 1)
	require.NoError(t, s.UpdateRecoveryState(ctx, recovery.Address, recovery.TransactionHash, "pending", common.RequestStatePending))
	readRecovery, err = s.ReadRecoveryByHash(ctx, recovery.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "pending", readRecovery.getState())
	require.NoError(t, s.UpdateRecoveryState(ctx, recovery.Address, recovery.TransactionHash, "done", common.RequestStateDone))
	readRecovery, err = s.ReadRecoveryByHash(ctx, recovery.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "done", readRecovery.getState())
	require.Panics(t, func() { s.UpdateRecoveryState(ctx, recovery.Address, recovery.TransactionHash, "raw", 0xff) })
	require.Panics(t, func() { (&Recovery{State: 0xff}).getState() })

	closed := &Recovery{
		Address: "closed-address", Chain: common.SafeChainBitcoin, Holder: "holder", Observer: "observer", RawTransaction: "raw",
		TransactionHash: crypto.Sha256Hash([]byte("closed-recovery")).String(), State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteInitialRecovery(ctx, closed))
	closedTx := coverageObserverTransaction("closed-recovery", common.RequestStateInitial, common.SafeChainBitcoin, now)
	closedTx.TransactionHash = closed.TransactionHash
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, closedTx))
	require.NoError(t, s.CloseRecoveryWithObserverKey(ctx, closed.Address, closed.TransactionHash, "observer-signature"))
	readRecovery, err = s.ReadRecoveryByHash(ctx, closed.TransactionHash)
	require.NoError(t, err)
	require.Equal(t, "failed", readRecovery.getState())

	atomicHash := crypto.Sha256Hash([]byte("atomic-finish")).String()
	atomicRecovery := &Recovery{
		Address: "atomic-address", Chain: common.SafeChainEthereum, Holder: "holder", Observer: "observer", RawTransaction: "initial",
		TransactionHash: atomicHash, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteInitialRecovery(ctx, atomicRecovery))
	require.NoError(t, s.UpdateRecoveryState(ctx, atomicRecovery.Address, atomicHash, "pending", common.RequestStatePending))
	atomicTx := coverageObserverTransaction("atomic-finish", common.RequestStatePending, common.SafeChainEthereum, now)
	require.NoError(t, s.WriteTransactionApprovalIfNotExists(ctx, atomicTx))
	require.NoError(t, s.FinishTransactionSignatures(ctx, atomicHash, "finished-atomically"))
	readRecovery, err = s.ReadRecoveryByHash(ctx, atomicHash)
	require.NoError(t, err)
	require.Equal(t, "done", readRecovery.getState())
	require.Equal(t, "finished-atomically", readRecovery.RawTransaction)
	finishedTx, err := s.ReadTransactionApproval(ctx, atomicHash)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateDone), finishedTx.State)

	orphanHash := crypto.Sha256Hash([]byte("orphan-recovery")).String()
	orphan := &Recovery{
		Address: "orphan-address", Chain: common.SafeChainEthereum, Holder: "holder", Observer: "observer", RawTransaction: "initial",
		TransactionHash: orphanHash, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteInitialRecovery(ctx, orphan))
	require.NoError(t, s.UpdateRecoveryState(ctx, orphan.Address, orphanHash, "pending", common.RequestStatePending))
	require.Error(t, s.FinishTransactionSignatures(ctx, orphanHash, "must-rollback"))
	readRecovery, err = s.ReadRecoveryByHash(ctx, orphanHash)
	require.NoError(t, err)
	require.Equal(t, "pending", readRecovery.getState())
	require.Equal(t, "pending", readRecovery.RawTransaction)

	private, _ := btcec.PrivKeyFromBytes([]byte{7})
	require.NoError(t, s.WriteAccountantKeys(ctx, common.CurveSecp256k1ECDSABitcoin, map[string]*btcec.PrivateKey{"accountant-address": private}))
	privateHex, err := s.ReadAccountantPrivateKey(ctx, "accountant-address")
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(private.Serialize()), privateHex)
	privateHex, err = s.ReadAccountantPrivateKey(ctx, "missing")
	require.NoError(t, err)
	require.Empty(t, privateHex)

	observerPublic := hex.EncodeToString(private.PubKey().SerializeCompressed())
	chainCode := crypto.Sha256Hash([]byte("chain-code"))
	publics := map[string]string{observerPublic: hex.EncodeToString(chainCode[:])}
	require.NoError(t, s.WriteObserverKeys(ctx, common.CurveSecp256k1ECDSABitcoin, publics))
	readPublic, readCode, err := s.ReadObserverKey(ctx, common.CurveSecp256k1ECDSABitcoin)
	require.NoError(t, err)
	require.Equal(t, observerPublic, readPublic)
	require.Equal(t, chainCode[:], readCode)
	require.NoError(t, s.DeleteObserverKey(ctx, observerPublic))
	readPublic, readCode, err = s.ReadObserverKey(ctx, common.CurveSecp256k1ECDSABitcoin)
	require.NoError(t, err)
	require.Empty(t, readPublic)
	require.Nil(t, readCode)
	require.Error(t, s.DeleteObserverKey(ctx, observerPublic))

	utxo := &Output{
		TransactionHash: crypto.Sha256Hash([]byte("utxo")).String(), Index: 1, Address: "accountant-address", Satoshi: 10_000,
		Chain: common.SafeChainBitcoin, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteBitcoinUTXOIfNotExists(ctx, utxo))
	require.NoError(t, s.WriteBitcoinUTXOIfNotExists(ctx, utxo))
	readOutput, err := s.ReadBitcoinUTXO(ctx, utxo.TransactionHash, int64(utxo.Index), utxo.Chain)
	require.NoError(t, err)
	require.Equal(t, utxo.Satoshi, readOutput.Satoshi)
	readOutput, err = s.ReadBitcoinUTXO(ctx, "missing", 0, utxo.Chain)
	require.NoError(t, err)
	require.Nil(t, readOutput)
	outputs, err := s.ReadBitcoinUTXOs(ctx, utxo.Chain)
	require.NoError(t, err)
	require.Len(t, outputs, 1)
	spending := coverageObserverTransaction("utxo-spend", common.RequestStateDone, utxo.Chain, now)
	assigned, err := s.AssignBitcoinUTXOByRangeForTransaction(ctx, 5_000, 15_000, spending)
	require.NoError(t, err)
	require.Equal(t, utxo.TransactionHash, assigned.TransactionHash)
	assignedAgain, err := s.AssignBitcoinUTXOByRangeForTransaction(ctx, 5_000, 15_000, spending)
	require.NoError(t, err)
	require.Equal(t, spending.TransactionHash, assignedAgain.SpentBy.String)
	none, err := s.AssignBitcoinUTXOByRangeForTransaction(ctx, 20_000, 30_000, coverageObserverTransaction("none", common.RequestStateDone, utxo.Chain, now))
	require.NoError(t, err)
	require.Nil(t, none)
	require.Panics(t, func() {
		invalid := *utxo
		invalid.TransactionHash = crypto.Sha256Hash([]byte("invalid-utxo")).String()
		invalid.State = common.RequestStateDone
		s.WriteBitcoinUTXOIfNotExists(ctx, &invalid)
	})

	feeInput := &Output{
		TransactionHash: crypto.Sha256Hash([]byte("fee-input")).String(), Index: 0, Address: "accountant-address", Satoshi: 2_000,
		Chain: common.SafeChainBitcoin, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteBitcoinUTXOIfNotExists(ctx, feeInput))
	previous, err := chainhash.NewHashFromStr(feeInput.TransactionHash)
	require.NoError(t, err)
	msgTx := wire.NewMsgTx(2)
	msgTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previous, feeInput.Index), nil, nil))
	msgTx.AddTxOut(wire.NewTxOut(1_000, []byte{0x51}))
	msgTx.AddTxOut(wire.NewTxOut(900, []byte{0x51}))
	require.NoError(t, s.WriteBitcoinFeeOutput(ctx, msgTx, "change-address", spending))
	createdHash := msgTx.TxHash().String()
	first, err := s.ReadBitcoinUTXO(ctx, createdHash, 0, common.SafeChainBitcoin)
	require.NoError(t, err)
	require.Equal(t, spending.TransactionHash, first.SpentBy.String)
	second, err := s.ReadBitcoinUTXO(ctx, createdHash, 1, common.SafeChainBitcoin)
	require.NoError(t, err)
	require.Equal(t, int64(900), second.Satoshi)
}

func TestCoverageObserverBitcoinAssignmentRetryKeepsSingleReservation(t *testing.T) {
	ctx := context.Background()
	s := coverageObserverStore(t)
	now := time.Now().UTC()
	spending := coverageObserverTransaction("reserved-transaction", common.RequestStateDone, common.SafeChainBitcoin, now)

	spare := &Output{
		TransactionHash: crypto.Sha256Hash([]byte("older-spare")).String(), Index: 0, Address: "accountant", Satoshi: 10_000,
		Chain: common.SafeChainBitcoin, State: common.RequestStateInitial, CreatedAt: now.Add(-time.Minute), UpdatedAt: now.Add(-time.Minute),
	}
	reserved := &Output{
		TransactionHash: crypto.Sha256Hash([]byte("reserved-output")).String(), Index: 0, Address: "accountant", Satoshi: 10_000,
		Chain: common.SafeChainBitcoin, State: common.RequestStateInitial, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, s.WriteBitcoinUTXOIfNotExists(ctx, spare))
	require.NoError(t, s.WriteBitcoinUTXOIfNotExists(ctx, reserved))
	_, err := s.db.Exec(
		"UPDATE bitcoin_outputs SET state=?,spent_by=? WHERE transaction_hash=? AND output_index=?",
		common.RequestStateDone, spending.TransactionHash, reserved.TransactionHash, reserved.Index,
	)
	require.NoError(t, err)

	assigned, err := s.AssignBitcoinUTXOByRangeForTransaction(ctx, 5_000, 15_000, spending)
	require.NoError(t, err)
	require.Equal(t, reserved.TransactionHash, assigned.TransactionHash)
	unchanged, err := s.ReadBitcoinUTXO(ctx, spare.TransactionHash, int64(spare.Index), spare.Chain)
	require.NoError(t, err)
	require.Equal(t, uint8(common.RequestStateInitial), unchanged.State)
	require.False(t, unchanged.SpentBy.Valid)
}

func TestCoverageObserverPureHelpersAndCheckpoints(t *testing.T) {
	ctx := context.Background()
	s := coverageObserverStore(t)
	conf := &Configuration{
		PrivateKey: "private", Timestamp: 123,
		CustomKeyPriceAmount: "1", OperationPriceAmount: "2", TransactionMinimum: "3",
		BitcoinRPC: "bitcoin", LitecoinRPC: "litecoin", EthereumRPC: "ethereum", PolygonRPC: "polygon",
	}
	require.NoError(t, conf.Validate())
	for _, mutate := range []func(*Configuration){
		func(c *Configuration) { c.CustomKeyPriceAmount = "0" },
		func(c *Configuration) { c.OperationPriceAmount = "0" },
		func(c *Configuration) { c.TransactionMinimum = "0" },
	} {
		copy := *conf
		mutate(&copy)
		require.Error(t, copy.Validate())
	}

	group := &mtg.Configuration{}
	group.Genesis.Members = []string{"z", "a", "m"}
	node := &Node{conf: conf, store: s, keeper: group}
	require.Equal(t, []string{"a", "m", "z"}, node.GetKeepers())
	require.Equal(t, "bitcoin", firstString(node.bitcoinParams(common.SafeChainBitcoin)))
	require.Equal(t, "litecoin", firstString(node.bitcoinParams(common.SafeChainLitecoin)))
	require.Equal(t, "ethereum", firstString(node.ethereumParams(common.SafeChainEthereum)))
	require.Equal(t, "polygon", firstString(node.ethereumParams(common.SafeChainPolygon)))
	require.Panics(t, func() { node.bitcoinParams(0xff) })
	require.Panics(t, func() { node.ethereumParams(0xff) })
	require.NotEmpty(t, node.bitcoinDummyHolder())
	require.Equal(t, node.safeTraceId("one", "two"), node.safeTraceId("one", "two"))

	for chain, expected := range map[byte][3]int64{
		common.SafeChainBitcoin:  {802220, 3, 2},
		common.SafeChainLitecoin: {2523300, 6, 4},
		common.SafeChainPolygon:  {52950000, 512, 32},
		common.SafeChainEthereum: {19175473, 32, 8},
	} {
		require.NotEmpty(t, depositCheckpointKey(chain))
		require.Equal(t, expected[0], depositCheckpointDefault(chain))
		require.Equal(t, expected[1], node.getChainFinalizationDelay(chain))
		require.Equal(t, expected[2], node.getChainBlockBatch(chain))
		checkpoint, err := node.readDepositCheckpoint(ctx, chain)
		require.NoError(t, err)
		require.Equal(t, expected[0], checkpoint)
		require.NoError(t, s.writeBlockCheckpoint(ctx, chain, expected[0]+10))
		checkpoint, err = node.readDepositCheckpoint(ctx, chain)
		require.NoError(t, err)
		require.Equal(t, expected[0]+10, checkpoint)
	}
	require.Panics(t, func() { depositCheckpointDefault(0xff) })
	require.Panics(t, func() { depositCheckpointKey(0xff) })
	require.Panics(t, func() { node.getChainFinalizationDelay(0xff) })
	require.Panics(t, func() { node.getChainBlockBatch(0xff) })

	snapshot, err := node.readSnapshotsCheckpoint(ctx)
	require.NoError(t, err)
	require.Equal(t, time.Unix(0, conf.Timestamp), snapshot)
	writtenSnapshot := time.Now().UTC().Truncate(time.Nanosecond)
	require.NoError(t, node.writeSnapshotsCheckpoint(ctx, writtenSnapshot))
	snapshot, err = node.readSnapshotsCheckpoint(ctx)
	require.NoError(t, err)
	require.Equal(t, writtenSnapshot, snapshot)
	withdrawal, err := node.readMixinWithdrawalsCheckpoint(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(77_000_000), withdrawal)
	require.NoError(t, node.writeMixinWithdrawalsCheckpoint(ctx, 88))
	withdrawal, err = node.readMixinWithdrawalsCheckpoint(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(88), withdrawal)

	key, err := node.chainKeygenRequestTimeKey(common.SafeChainBitcoin)
	require.NoError(t, err)
	require.Equal(t, bitcoinKeygenRequestTimeKey, key)
	key, err = node.chainKeygenRequestTimeKey(common.SafeChainEthereum)
	require.NoError(t, err)
	require.Equal(t, ethereumKeygenRequestTimeKey, key)
	_, err = node.chainKeygenRequestTimeKey(0xff)
	require.Error(t, err)
	requestTime, err := node.readSignerKeygenRequestTime(ctx, common.SafeChainBitcoin)
	require.NoError(t, err)
	require.Equal(t, time.Unix(0, conf.Timestamp), requestTime)
	require.NoError(t, node.writeSignerKeygenRequestTime(ctx, common.SafeChainBitcoin))
	requestTime, err = node.readSignerKeygenRequestTime(ctx, common.SafeChainBitcoin)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), requestTime, time.Second)

	message := "🧱🧱🧱🧱🧱 Keeper 🧱🧱🧱🧱🧱\n⏲️ Run time: 2h\n⏲️ Group: safe\n🎆 Latest request: request\n🦷 Binary version: v1"
	stats := parseNodeStats(base64.RawURLEncoding.EncodeToString([]byte(message)))
	require.Equal(t, NodeTypeKeeper, stats.Type)
	require.Equal(t, "2h", stats.Runtime)
	require.Equal(t, "safe", stats.Group)
	require.Equal(t, "v1", stats.App.Version)
	require.Nil(t, parseNodeStats("%%%"))
	require.Nil(t, parseNodeStats(base64.RawURLEncoding.EncodeToString([]byte("unknown"))))

	require.False(t, checkGoodAsset(nil))
	require.False(t, checkGoodAsset(&Asset{IconURL: DefaultIconUrl, PriceUSD: "1"}))
	require.False(t, checkGoodAsset(&Asset{IconURL: "icon", PriceUSD: "invalid"}))
	require.False(t, checkGoodAsset(&Asset{IconURL: "icon", PriceUSD: "0"}))
	require.True(t, checkGoodAsset(&Asset{IconURL: "icon", PriceUSD: "1"}))

	assetID := uuid.Must(uuid.NewV4()).String()
	deposit := &Deposit{
		TransactionHash: crypto.Sha256Hash([]byte("keeper-extra")).String(), OutputIndex: 2, AssetId: assetID,
		AssetAddress: "0x1111111111111111111111111111111111111111", Amount: "1.25", Chain: common.SafeChainBitcoin,
	}
	require.Equal(t, "125000000", deposit.bigAmount(bitcoin.ValuePrecision).String())
	require.NotEmpty(t, deposit.encodeKeeperExtra(bitcoin.ValuePrecision))
	require.Panics(t, func() { deposit.bigAmount(bitcoin.ValuePrecision - 1) })
	deposit.Chain = common.SafeChainEthereum
	require.Equal(t, "1250000", deposit.bigAmount(6).String())
	require.NotEmpty(t, deposit.encodeKeeperExtra(6))
	deposit.Chain = 0xff
	require.Panics(t, func() { deposit.bigAmount(8) })

	views := viewOutputs([]*bitcoin.Input{{TransactionHash: "hash", Index: 1, Satoshi: 2, Script: []byte{1, 2}, Sequence: 3}})
	require.Len(t, views, 1)
	require.Equal(t, "0102", views[0].Script)
	recoveryViews := node.viewRecoveries(ctx, []*Recovery{{Address: "address", State: common.RequestStateDone}})
	require.Equal(t, "done", recoveryViews[0]["state"])
	depositViews := node.viewDeposits(ctx, []*Deposit{{TransactionHash: "hash", State: common.RequestStateInitial, Chain: common.SafeChainEthereum}}, nil)
	require.Equal(t, "pending", depositViews[0]["state"])
	require.Equal(t, "hash", depositViews[0]["sent_hash"])
}

func TestCoverageObserverHTTPAndEarlyNodeBranches(t *testing.T) {
	ctx := common.EnableTestEnvironment(context.Background())
	s := coverageObserverStore(t)
	kd, err := keeperstore.OpenSQLite3Store(t.TempDir() + "/keeper.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, kd.Close()) })
	conf := &Configuration{
		Timestamp: 1, CustomKeyPriceAssetId: "custom-asset", CustomKeyPriceAmount: "1",
		OperationPriceAmount: "1", TransactionMinimum: "1",
	}
	conf.App.AppId = "observer-app"
	conf.App.SessionId = "session"
	conf.App.ServerPublicKey = "server"
	conf.App.SessionPrivateKey = "session-private"
	conf.App.SpendPrivateKey = "spend"
	conf.App.IsSpendKeyCanonical = true
	group := &mtg.Configuration{}
	group.Genesis.Members = []string{"member"}
	group.Genesis.Threshold = 1
	node := &Node{conf: conf, store: s, keeperStore: kd, keeper: group}

	call := func(method, target, body string, handler func(http.ResponseWriter, *http.Request, map[string]string), params map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(ctx)
		handler(recorder, request, params)
		return recorder
	}

	request := httptest.NewRequest(http.MethodGet, "https://safe.mixin.dev/", nil).WithContext(ctx)
	request.Host = "safe.mixin.dev"
	recorder := httptest.NewRecorder()
	node.httpIndex(recorder, request, nil)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Header().Get("Content-Type"), "text/html")
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/favicon.ico", "", node.httpFavicon, nil).Code)
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/chains", "", node.httpListChains, nil).Code)
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/signers", "", node.httpListSigners, nil).Code)
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/keepers", "", node.httpListKeepers, nil).Code)
	require.Panics(t, func() { node.httpListNodes(httptest.NewRecorder(), request, "invalid") })

	require.Equal(t, http.StatusBadRequest, call(http.MethodGet, "/deposits", "", node.httpListDeposits, nil).Code)
	target := fmt.Sprintf("/deposits?chain=%d", common.SafeChainBitcoin)
	require.Equal(t, http.StatusOK, call(http.MethodGet, target, "", node.httpListDeposits, nil).Code)
	require.Equal(t, http.StatusOK, call(http.MethodGet, "/recoveries", "", node.httpListRecoveries, nil).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/recoveries/missing", "", node.httpGetRecovery, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/accounts/missing", "", node.httpGetAccount, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/accounts/missing/inheritances", "", node.httpListInheritances, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/transactions/missing", "", node.httpGetTransaction, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodGet, "/keys/missing", "", node.httpGetCustomKey, map[string]string{"public": "missing"}).Code)

	for _, test := range []struct {
		handler func(http.ResponseWriter, *http.Request, map[string]string)
		params  map[string]string
	}{
		{node.httpApproveAccount, map[string]string{"id": "missing"}},
		{node.httpSignRecovery, map[string]string{"id": "missing"}},
		{node.httpApproveTransaction, map[string]string{"id": "missing"}},
		{node.httpCreateInheritanceTransaction, nil},
	} {
		require.Equal(t, http.StatusBadRequest, call(http.MethodPost, "/", "{", test.handler, test.params).Code)
	}
	require.Equal(t, http.StatusNotFound, call(http.MethodPost, "/", "{}", node.httpApproveAccount, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodPost, "/", "{}", node.httpSignRecovery, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodPost, "/", "{}", node.httpApproveTransaction, map[string]string{"id": "missing"}).Code)
	require.Equal(t, http.StatusNotFound, call(http.MethodPost, "/", "{}", node.httpCreateInheritanceTransaction, nil).Code)

	count, satoshi, err := node.readChainAccountantBalance(ctx, int(common.SafeChainBitcoin))
	require.NoError(t, err)
	require.Zero(t, count)
	require.Zero(t, satoshi)
	sp, req, err := node.readSafeProposalOrRequest(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, sp)
	require.Nil(t, req)
	tx, req, err := node.readTransactionOrRequest(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, tx)
	require.Nil(t, req)
	outputs, err := node.listAllBitcoinUTXOsForHolder(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, outputs)
	outputs, err = node.listPendingBitcoinUTXOsForHolder(ctx, "missing")
	require.NoError(t, err)
	require.Nil(t, outputs)

	user := node.safeUser()
	require.Equal(t, conf.App.AppId, user.UserId)
	require.Equal(t, conf.App.IsSpendKeyCanonical, user.IsSpendPrivateSum)
	require.NoError(t, s.WriteAccountProposalIfNotExists(ctx, "approval-account", time.Now()))
	require.NoError(t, node.saveAccountApprovalSignature(ctx, "approval-account", "signature"))
	require.Error(t, node.httpCreateSafeAccountRecoveryRequest(ctx, "missing", "", ""))
	require.Error(t, node.httpCreateSafeAccountRecoveryRequest(ctx, "missing", "raw", "hash"))
	require.Error(t, node.httpSignAccountRecoveryRequest(ctx, "missing", "raw", "hash"))
	require.Error(t, node.httpCloseAccountRecoveryRequest(ctx, "missing", "id", "sig", "hash"))
	require.Error(t, node.httpApproveSafeTransaction(ctx, 0xff, "raw"))
	require.Error(t, node.httpRevokeSafeTransaction(ctx, 0xff, "hash", "sig"))
	require.NoError(t, node.holderPayTransactionApproval(ctx, common.SafeChainBitcoin, "missing"))

	trusted, err := node.checkTrustedSender(ctx, "bc1ql24x05zhqrpejar0p3kevhu48yhnnr3r95sv4y")
	require.NoError(t, err)
	require.True(t, trusted)
	trusted, err = node.checkTrustedSender(ctx, "missing")
	require.NoError(t, err)
	require.False(t, trusted)
	require.False(t, node.isTxStuck(ctx, &Transaction{Chain: common.SafeChainBitcoin}))
	require.False(t, node.isTxStuck(ctx, &Transaction{Chain: common.SafeChainEthereum, State: common.RequestStateInitial}))
	require.False(t, node.isTxStuck(ctx, &Transaction{Chain: common.SafeChainEthereum, State: common.RequestStateDone, SpentHash: sql.NullString{Valid: true, String: "spent"}}))
	require.False(t, node.isTxStuck(ctx, &Transaction{Chain: common.SafeChainEthereum, State: common.RequestStateDone, UpdatedAt: time.Now()}))
	require.Error(t, func() error {
		_, err := node.ethereumSpendFullySignedTransaction(ctx, &Transaction{RawTransaction: "not-hex"})
		return err
	}())

	handlerCalled := false
	handler := mixinBlazeHandler(func(context.Context, bot.MessageView, string) error {
		handlerCalled = true
		return nil
	})
	require.NoError(t, handler.OnMessage(ctx, bot.MessageView{}, "client"))
	require.True(t, handlerCalled)
	require.NoError(t, handler.OnAckReceipt(ctx, bot.MessageView{}, "client"))
	require.True(t, handler.SyncAck())
	require.NoError(t, node.handleMessage(ctx, bot.MessageView{ConversationId: "other"}))

	handled, err := node.handleCustomObserverKeyRegistration(ctx, &mixin.SafeSnapshot{AssetID: "other"})
	require.NoError(t, err)
	require.False(t, handled)
	handled, err = node.handleCustomObserverKeyRegistration(ctx, &mixin.SafeSnapshot{AssetID: conf.CustomKeyPriceAssetId, Memo: "invalid"})
	require.NoError(t, err)
	require.False(t, handled)
	extra := make([]byte, 66)
	extra[0] = 0xff
	handled, err = node.handleCustomObserverKeyRegistration(ctx, &mixin.SafeSnapshot{
		AssetID: conf.CustomKeyPriceAssetId, Memo: base64.RawURLEncoding.EncodeToString(extra), Amount: decimal.NewFromInt(2),
	})
	require.NoError(t, err)
	require.False(t, handled)
	extra[0] = common.CurveSecp256k1ECDSABitcoin
	handled, err = node.handleCustomObserverKeyRegistration(ctx, &mixin.SafeSnapshot{
		AssetID: conf.CustomKeyPriceAssetId, Memo: base64.RawURLEncoding.EncodeToString(extra), Amount: decimal.Zero,
	})
	require.NoError(t, err)
	require.True(t, handled)
	handled, err = node.handleTransactionApprovalPayment(ctx, &mixin.SafeSnapshot{Memo: "missing"})
	require.NoError(t, err)
	require.False(t, handled)
	handled, err = node.handleKeeperResponse(ctx, &mixin.SafeSnapshot{Memo: "invalid"})
	require.NoError(t, err)
	require.False(t, handled)

	signers := (&Transaction{State: common.RequestStateFailed}).Signers(ctx, node, &keeperstore.Safe{})
	require.Empty(t, signers)
}

func coverageObserverStore(t *testing.T) *SQLite3Store {
	t.Helper()
	s, err := OpenSQLite3Store(t.TempDir() + "/observer.sqlite3")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func coverageObserverTransaction(name string, state byte, chain byte, at time.Time) *Transaction {
	return &Transaction{
		TransactionHash: crypto.Sha256Hash([]byte(name)).String(), RawTransaction: "raw", Chain: chain,
		Holder: "holder-" + name, Signer: "signer", State: state, CreatedAt: at, UpdatedAt: at,
	}
}

func firstString(first string, _ string) string {
	return first
}
