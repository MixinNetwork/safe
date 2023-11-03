package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

const (
	ethereumKeygenRequestTimeKey = "ethereum-keygen-request-time"
)

type Transfer struct {
	Index    int64
	Receiver string
	Value    *big.Int
}

func ethereumMixinSnapshotsCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainMVM:
	default:
		panic(chain)
	}
	return fmt.Sprintf("ethereum-mixin-snapshots-checkpoint-%d", chain)
}

func ethereumDepositCheckpointKey(chain byte) string {
	switch chain {
	case keeper.SafeChainMVM:
	default:
		panic(chain)
	}
	return fmt.Sprintf("ethereum-deposit-checkpoint-%d", chain)
}

func ethereumDepositCheckpointDefault(chain byte) int64 {
	switch chain {
	case keeper.SafeChainMVM:
		return 43690750
	default:
		panic(chain)
	}
}

func (node *Node) deployEthereumGnosisSafeAccount(ctx context.Context, data []byte) error {
	logger.Printf("node.deployEthereumGnosisSafeAccount(%x)", data)
	gs, err := ethereum.UnmarshalGnosisSafe(data)
	if err != nil {
		return fmt.Errorf("ethereum.UnmarshalGnosisSafe(%x) => %v", data, err)
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, gs.Address)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeProposalByAddress(%s) => %v", gs.Address, err)
	}
	safe, err := node.keeperStore.ReadSafe(ctx, sp.Holder)
	if err != nil || safe == nil {
		return fmt.Errorf("keeperStore.ReadSafe(%s) => %v", gs.Address, err)
	}
	rpc, ethereumAssetId := node.ethereumParams(safe.Chain)
	_, err = node.checkOrDeployKeeperBond(ctx, ethereumAssetId, sp.Holder)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", ethereumAssetId, sp.Holder, err)
	if err != nil {
		return err
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, gs.TxHash)
	if err != nil || tx == nil {
		return fmt.Errorf("keeperStore.ReadTransaction(%s) => %v %v", gs.TxHash, tx, err)
	}
	raw, err := hex.DecodeString(tx.RawTransaction)
	if err != nil {
		return err
	}
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%s) => %v %v", tx.RawTransaction, t, err)
	if err != nil {
		return err
	}
	owners, pubs := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v %v", safe.Holder, safe.Signer, safe.Observer, owners, pubs)
	var index int64
	for i, pub := range pubs {
		if pub == safe.Observer {
			index = int64(i)
		}
	}
	timelock := int64(safe.Timelock / time.Hour)
	chainId := ethereum.GetEvmChainID(int64(safe.Chain))
	sa, err := ethereum.GetOrDeploySafeAccount(rpc, node.conf.EVMKey, chainId, owners, 2, timelock, index, t)
	logger.Printf("ethereum.GetOrDeploySafeAccount(%s, %d, %v, %d, %d, %v) => %s %v", rpc, chainId, owners, 2, timelock, t, sa, err)
	return err
}

func (node *Node) ethereumParams(chain byte) (string, string) {
	switch chain {
	case keeper.SafeChainEthereum:
		return node.conf.EthereumRPC, keeper.SafeEthereumChainId
	case keeper.SafeChainMVM:
		return node.conf.MVMRPC, keeper.SafeMVMChainId
	default:
		panic(chain)
	}
}

func (node *Node) ethereumNetworkInfoLoop(ctx context.Context, chain byte) {
	rpc, assetId := node.ethereumParams(chain)

	for {
		time.Sleep(keeper.SafeNetworkInfoTimeout / 7)
		height, err := ethereum.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		gasPrice, err := ethereum.RPCGetGasPrice(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCEstimateSmartFee(%d) => %v", chain, err)
			continue
		}
		blockHash, err := ethereum.RPCGetBlockHash(rpc, height)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHash(%d, %d) => %v", chain, height, err)
			continue
		}
		if strings.HasSuffix(blockHash, "0x") {
			blockHash = blockHash[2:]
		}
		hash, err := crypto.HashFromString(blockHash)
		if err != nil {
			panic(err)
		}
		extra := []byte{chain}
		extra = binary.BigEndian.AppendUint64(extra, gasPrice.Uint64())
		extra = binary.BigEndian.AppendUint64(extra, uint64(height))
		extra = append(extra, hash[:]...)
		id := mixin.UniqueConversationID(assetId, fmt.Sprintf("%s:%d", blockHash, height))
		id = mixin.UniqueConversationID(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), gasPrice.Uint64()))
		logger.Printf("node.ethereumNetworkInfoLoop(%d) => %d %d %s %s", chain, height, gasPrice.Uint64(), blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendKeeperResponse(ctx, dummy, byte(action), chain, id, extra)
		logger.Verbosef("node.sendKeeperResponse(%d, %s, %x) => %v", chain, id, extra, err)
	}
}

func (node *Node) ethereumReadBlock(ctx context.Context, num int64, chain byte) ([]*ethereum.RPCTransaction, error) {
	rpc, _ := node.ethereumParams(chain)

	hash, err := ethereum.RPCGetBlockHash(rpc, num)
	if err != nil {
		return nil, err
	}
	block, err := ethereum.RPCGetBlockWithTransactions(rpc, hash)
	if err != nil {
		return nil, err
	}
	return block.Tx, nil
}

func (node *Node) ethereumWritePendingDeposit(ctx context.Context, transfer *Transfer, tx *ethereum.RPCTransaction, chain byte) error {
	_, assetId := node.ethereumParams(chain)
	amount := decimal.NewFromBigInt(transfer.Value, -ethereum.ValuePrecision)

	sent, err := node.store.QueryDepositSentHashes(ctx, []*Deposit{{TransactionHash: tx.Hash}})
	logger.Printf("store.QueryDepositSentHashes(%s) => %v %v", tx.Hash, sent, err)
	if err != nil {
		return fmt.Errorf("store.QueryDepositSentHashes(%s) => %v", tx.Hash, err)
	}
	if sent[tx.Hash] != "" {
		return nil
	}

	old, err := node.keeperStore.ReadDeposit(ctx, tx.Hash, transfer.Index, assetId, transfer.Receiver)
	logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", tx.Hash, transfer.Index, assetId, transfer.Receiver, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", tx.Hash, transfer.Index, assetId, transfer.Receiver, old, err)
	} else if old != nil {
		return nil
	}

	safe, err := node.keeperStore.ReadSafeByAddress(ctx, transfer.Receiver)
	logger.Printf("keeperStore.ReadSafeByAddress(%s) => %v %v", transfer.Receiver, safe, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", transfer.Receiver, err)
	} else if safe == nil {
		return nil
	}

	createdAt := time.Now().UTC()
	deposit := &Deposit{
		TransactionHash: tx.Hash,
		OutputIndex:     transfer.Index,
		AssetId:         assetId,
		Amount:          amount.String(),
		Receiver:        transfer.Receiver,
		Sender:          tx.From,
		Holder:          safe.Holder,
		Category:        common.ActionObserverHolderDeposit,
		State:           common.RequestStateInitial,
		Chain:           chain,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}

	err = node.store.WritePendingDepositIfNotExists(ctx, deposit)
	if err != nil {
		return fmt.Errorf("store.WritePendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) ethereumConfirmPendingDeposit(ctx context.Context, deposit *Deposit) error {
	rpc, assetId := node.ethereumParams(deposit.Chain)

	bonded, err := node.checkOrDeployKeeperBond(ctx, assetId, deposit.Holder)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}

	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, deposit.Chain, time.Now())
	if err != nil {
		return fmt.Errorf("keeperStore.ReadLatestNetworkInfo(%d) => %v", deposit.Chain, err)
	} else if info == nil {
		return nil
	}
	if info.CreatedAt.Add(keeper.SafeNetworkInfoTimeout / 7).Before(time.Now()) {
		return nil
	}
	if info.CreatedAt.After(time.Now()) {
		panic(fmt.Errorf("malicious ethereum network info %v", info))
	}

	tx, err := ethereum.RPCGetTransactionByHash(rpc, deposit.TransactionHash)
	if err != nil || tx == nil {
		panic(fmt.Errorf("malicious ethereum deposit or node not in sync? %s %v", deposit.TransactionHash, err))
	}
	traces, err := ethereum.RPCDebugTraceTransactionByHash(rpc, deposit.TransactionHash)
	if err != nil {
		return err
	}
	transfers := loopCalls(traces, 0, 0)
	match := false
	for _, t := range transfers {
		if t.Receiver == deposit.Receiver && ethereum.ParseWei(deposit.Amount).Cmp(t.Value) == 0 {
			match = true
		}
	}
	if !match {
		panic(fmt.Errorf("malicious ethereum deposit %s", deposit.TransactionHash))
	}
	confirmations := info.Height - tx.BlockHeight + 1
	if info.Height < tx.BlockHeight {
		confirmations = 0
	}
	isSafe, err := node.checkSafeInternalAddress(ctx, deposit.Sender)
	if err != nil {
		return fmt.Errorf("node.checkSafeInternalAddress(%s) => %v", deposit.Sender, err)
	}
	if isSafe {
		confirmations = 1000000
	}
	if confirmations < ethereum.TransactionConfirmations {
		return nil
	}

	extra := deposit.encodeKeeperExtra()
	id := mixin.UniqueConversationID(assetId, deposit.Holder)
	id = mixin.UniqueConversationID(id, fmt.Sprintf("%s:%d", deposit.TransactionHash, deposit.OutputIndex))
	err = node.sendKeeperResponse(ctx, deposit.Holder, deposit.Category, deposit.Chain, id, extra)
	if err != nil {
		return fmt.Errorf("node.sendKeeperResponse(%s) => %v", id, err)
	}
	err = node.store.ConfirmPendingDeposit(ctx, deposit.TransactionHash, deposit.OutputIndex)
	if err != nil {
		return fmt.Errorf("store.ConfirmPendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) ethereumDepositConfirmLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(3 * time.Second)
		deposits, err := node.store.ListDeposits(ctx, int(chain), "", common.RequestStateInitial, 0)
		if err != nil {
			panic(err)
		}
		for _, d := range deposits {
			err := node.ethereumConfirmPendingDeposit(ctx, d)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) ethereumMixinWithdrawalsLoop(ctx context.Context, chain byte) {
	_, assetId := node.ethereumParams(chain)

	for {
		time.Sleep(time.Second)
		checkpoint, err := node.ethereumReadMixinSnapshotsCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		snapshots, err := node.mixin.ReadNetworkSnapshots(ctx, assetId, checkpoint, "ASC", 100)
		if err != nil {
			continue
		}

		for _, s := range snapshots {
			checkpoint = s.CreatedAt
			if s.Source != "WITHDRAWAL_INITIALIZED" {
				continue
			}
			err = node.ethereumProcessMixinSnapshot(ctx, s.SnapshotID, chain)
			logger.Printf("node.ethereumProcessMixinSnapshot(%d, %v) => %v", chain, s, err)
			if err != nil {
				panic(err)
			}
		}
		if len(snapshots) < 100 {
			time.Sleep(time.Second)
		}

		err = node.ethereumWriteMixinSnapshotsCheckpoint(ctx, checkpoint, chain)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) ethereumProcessMixinSnapshot(ctx context.Context, id string, chain byte) error {
	rpc, _ := node.ethereumParams(chain)
	s, err := node.mixin.ReadNetworkSnapshot(ctx, id)
	if err != nil {
		time.Sleep(time.Second)
		logger.Printf("mixin.ReadNetworkSnapshot(%s) => %v", id, err)
		return node.ethereumProcessMixinSnapshot(ctx, id, chain)
	}
	if s.SnapshotHash == "" || s.TransactionHash == "" {
		time.Sleep(2 * time.Second)
		return node.ethereumProcessMixinSnapshot(ctx, id, chain)
	}

	tx, err := ethereum.RPCGetTransactionByHash(rpc, s.TransactionHash)
	if err != nil || tx == nil {
		time.Sleep(2 * time.Second)
		logger.Printf("ethereum.RPCGetTransactionByHash(%s, %s) => %v %v", id, s.TransactionHash, tx, err)
		return node.ethereumProcessMixinSnapshot(ctx, id, chain)
	}

	return node.ethereumProcessTransaction(ctx, tx, chain)
}

func (node *Node) ethereumRPCBlocksLoop(ctx context.Context, chain byte) {
	rpc, _ := node.ethereumParams(chain)

	for {
		time.Sleep(3 * time.Second)
		checkpoint, err := node.ethereumReadDepositCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		height, err := ethereum.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		logger.Printf("node.ethereumReadDepositCheckpoint(%d) => %d %d", chain, checkpoint, height)
		if checkpoint > height {
			continue
		}
		txs, err := node.ethereumReadBlock(ctx, checkpoint, chain)
		logger.Printf("node.ethereumReadBlock(%d, %d) => %d %v", chain, checkpoint, len(txs), err)
		if err != nil {
			continue
		}

		for _, tx := range txs {
			for {
				err := node.ethereumProcessTransaction(ctx, tx, chain)
				if err == nil {
					break
				}
				logger.Printf("node.ethereumProcessTransaction(%s) => %v", tx.Hash, err)
			}
		}

		err = node.ethereumWriteDepositCheckpoint(ctx, checkpoint+1, chain)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) ethereumReadMixinSnapshotsCheckpoint(ctx context.Context, chain byte) (time.Time, error) {
	ckt, err := node.store.ReadProperty(ctx, ethereumMixinSnapshotsCheckpointKey(chain))
	if err != nil || ckt == "" {
		return time.Now(), err
	}
	return time.Parse(time.RFC3339Nano, ckt)
}

func (node *Node) ethereumProcessTransaction(ctx context.Context, tx *ethereum.RPCTransaction, chain byte) error {
	rpc, _ := node.ethereumParams(chain)
	traces, err := ethereum.RPCDebugTraceTransactionByHash(rpc, tx.Hash)
	if err != nil {
		return err
	}
	transfers := loopCalls(traces, 0, 0)
	for _, transfer := range transfers {
		err := node.ethereumWritePendingDeposit(ctx, transfer, tx, chain)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func loopCalls(trace *ethereum.RPCTransactionCallTrace, layer, index int) []*Transfer {
	var transfers []*Transfer

	if trace.Value != "" && trace.Input == "0x" {
		value, _ := new(big.Int).SetString(trace.Value[2:], 16)
		if value.Cmp(big.NewInt(0)) > 0 {
			transfers = append(transfers, &Transfer{
				Index:    int64(layer*10 + index),
				Value:    value,
				Receiver: trace.To,
			})
		}
	}

	for i, c := range trace.Calls {
		ts := loopCalls(c, layer+1, i)
		for _, t := range ts {
			transfers = append(transfers, t)
		}
	}
	return transfers
}

func (node *Node) ethereumReadDepositCheckpoint(ctx context.Context, chain byte) (int64, error) {
	min := ethereumDepositCheckpointDefault(chain)
	ckt, err := node.store.ReadProperty(ctx, ethereumDepositCheckpointKey(chain))
	if err != nil || ckt == "" {
		return min, err
	}
	checkpoint, err := strconv.ParseInt(ckt, 10, 64)
	if err != nil {
		panic(ckt)
	}
	if checkpoint < min {
		checkpoint = min
	}
	return checkpoint, nil
}

func (node *Node) ethereumWriteDepositCheckpoint(ctx context.Context, num int64, chain byte) error {
	return node.store.WriteProperty(ctx, ethereumDepositCheckpointKey(chain), fmt.Sprint(num))
}

func (node *Node) ethereumWriteMixinSnapshotsCheckpoint(ctx context.Context, offset time.Time, chain byte) error {
	return node.store.WriteProperty(ctx, ethereumMixinSnapshotsCheckpointKey(chain), offset.Format(time.RFC3339Nano))
}

func (node *Node) ethereumTransactionApprovalLoop(ctx context.Context, chain byte) {
	for {
		time.Sleep(3 * time.Second)
		approvals, err := node.store.ListPendingTransactionApprovals(ctx, chain)
		if err != nil {
			panic(err)
		}
		for _, approval := range approvals {
			err := node.sendToKeeperEthereumApproveTransaction(ctx, approval)
			logger.Verbosef("node.sendToKeeperEthereumApproveTransaction(%v) => %v", approval, err)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) sendToKeeperEthereumApproveTransaction(ctx context.Context, approval *Transaction) error {
	signed, err := node.ethereumCheckKeeperSignedTransaction(ctx, approval)
	logger.Printf("node.ethereumCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
	if err != nil || signed {
		return err
	}
	if !ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		panic(approval.RawTransaction)
	}

	rawId := mixin.UniqueConversationID(approval.RawTransaction, approval.RawTransaction)
	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	raw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), raw...)
	raw = common.AESEncrypt(node.aesKey[:], raw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(raw)
	traceId := mixin.UniqueConversationID(msg, msg)
	conf := node.conf.App
	rs, err := common.CreateObjectUntilSufficient(ctx, msg, traceId, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
	if err != nil {
		return err
	}
	ref, err := crypto.HashFromString(rs.TransactionHash)
	if err != nil {
		return err
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
	if err != nil {
		return err
	}
	id := mixin.UniqueConversationID(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), ref[:]...)
	references := []crypto.Hash{ref}
	action := common.ActionEthereumSafeApproveTransaction
	err = node.sendKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout).After(time.Now()) {
		return nil
	}
	id = mixin.UniqueConversationID(id, approval.UpdatedAt.String())
	err = node.sendKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}
	return node.store.UpdateTransactionApprovalRequestTime(ctx, approval.TransactionHash)
}

func (node *Node) ethereumCheckKeeperSignedTransaction(ctx context.Context, approval *Transaction) (bool, error) {
	requests, err := node.keeperStore.ListAllSignaturesForTransaction(ctx, approval.TransactionHash, common.RequestStateDone)
	if err != nil {
		return false, err
	}
	if len(requests) != 1 {
		return false, err
	}
	sig := common.DecodeHexOrPanic(requests[0].Signature.String)
	if len(sig) < 32 {
		return false, nil
	}
	return true, nil
}

func (node *Node) httpCreateEthereumAccountRecoveryRequest(ctx context.Context, safe *store.Safe, raw, hash string) error {
	approval, err := node.store.ReadTransactionApproval(ctx, hash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
	if err != nil {
		return err
	}
	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	if err != nil {
		return err
	}

	rb := common.DecodeHexOrPanic(raw)
	st, err := ethereum.UnmarshalSafeTransaction(rb)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%v) => %v %v", raw, st, err)
	if err != nil {
		return err
	}
	if st.Destination.Hex() == safe.Address {
		return fmt.Errorf("recovery destination %s is the same as safe address %s", st.Destination.Hex(), safe.Address)
	}

	switch {
	case approval != nil: // Close account with safeBTC
		if count != 1 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		if approval.State != common.RequestStateInitial {
			return nil
		}
		if approval.TransactionHash != hash {
			return nil
		}
		if approval.RawTransaction != raw {
			return nil
		}
		if ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
			return nil
		}

		tx, err := node.keeperStore.ReadTransaction(ctx, hash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", hash, tx, err)
		if err != nil || tx == nil {
			return err
		}
	case approval == nil: // Close account with holder key
		if count != 0 {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}

		if !ethereum.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return nil
		}
	}

	rpc, assetId := node.ethereumParams(safe.Chain)
	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, safe.Chain, time.Now())
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
	}
	latest, err := ethereum.RPCGetBlock(rpc, info.Hash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, info.Hash, latest, err)
	if err != nil {
		return err
	}
	safeBalance, err := node.keeperStore.ReadEthereumBalance(ctx, safe.Address, assetId)
	logger.Printf("store.ReadEthereumBalance(%s %s) => %v %v", safe.Address, assetId, safeBalance, err)
	if err != nil {
		return err
	}
	transaction, err := ethereum.RPCGetTransactionByHash(rpc, safeBalance.LatestTxHash)
	logger.Printf("ethereum.RPCGetTransactionByHash(%s %s) => %v %v", rpc, safeBalance.LatestTxHash, transaction, err)
	if err != nil {
		return err
	}
	block, err := ethereum.RPCGetBlock(rpc, transaction.BlockHash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, transaction.BlockHash, block, err)
	if err != nil {
		return err
	}
	if block.Time.IsZero() || latest.Time.IsZero() || block.Time.Add(safe.Timelock+1*time.Hour).After(latest.Time) {
		return fmt.Errorf("safe %s is locked", safe.Address)
	}
	if safeBalance.Balance.Cmp(st.Value) != 0 {
		return fmt.Errorf("recovery amount %d is not equal to balance %d ", st.Value, safeBalance.Balance)
	}

	if approval == nil {
		approval = &Transaction{
			TransactionHash: hash,
			RawTransaction:  raw,
			Chain:           safe.Chain,
			Holder:          safe.Holder,
			Signer:          safe.Signer,
			State:           common.RequestStateInitial,
			CreatedAt:       time.Now().UTC(),
			UpdatedAt:       time.Now().UTC(),
		}
		err = node.store.WriteTransactionApprovalIfNotExists(ctx, approval)
		if err != nil {
			return err
		}
	}

	r := &Recovery{
		Address:         safe.Address,
		Chain:           safe.Chain,
		Holder:          safe.Holder,
		Observer:        safe.Observer,
		RawTransaction:  raw,
		TransactionHash: hash,
		State:           common.RequestStateInitial,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	return node.store.WriteInitialRecovery(ctx, r)
}

func (node *Node) httpSignEthereumAccountRecoveryRequest(ctx context.Context, safe *store.Safe, raw, hash string) error {
	approval, err := node.store.ReadTransactionApproval(ctx, hash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.TransactionHash != hash {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}

	isHolderSigned := ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Holder)
	if !ethereum.CheckTransactionPartiallySignedBy(raw, safe.Observer) {
		return fmt.Errorf("ethereum.CheckTransactionPartiallySignedBy(%s, %s) observer", raw, safe.Observer)
	}

	rb := common.DecodeHexOrPanic(raw)
	st, err := ethereum.UnmarshalSafeTransaction(rb)
	if err != nil {
		return err
	}
	if st.Destination.Hex() == safe.Address {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	signedRaw := st.Marshal()

	rpc, assetId := node.ethereumParams(safe.Chain)
	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, safe.Chain, time.Now())
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil {
		return err
	}
	if info == nil {
		return nil
	}
	latest, err := ethereum.RPCGetBlock(rpc, info.Hash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, info.Hash, latest, err)
	if err != nil {
		return err
	}
	safeBalance, err := node.keeperStore.ReadEthereumBalance(ctx, safe.Address, assetId)
	logger.Printf("store.ReadEthereumBalance(%s %s) => %v %v", safe.Address, assetId, safeBalance, err)
	if err != nil {
		return err
	}
	transaction, err := ethereum.RPCGetTransactionByHash(rpc, safeBalance.LatestTxHash)
	logger.Printf("ethereum.RPCGetTransactionByHash(%s %s) => %v %v", rpc, safeBalance.LatestTxHash, transaction, err)
	if err != nil {
		return err
	}
	block, err := ethereum.RPCGetBlock(rpc, transaction.BlockHash)
	logger.Printf("ethereum.RPCGetBlock(%s %s) => %v %v", rpc, transaction.BlockHash, block, err)
	if err != nil {
		return err
	}
	if block.Time.IsZero() || latest.Time.IsZero() || block.Time.Add(safe.Timelock+1*time.Hour).After(latest.Time) {
		return fmt.Errorf("safe %s is locked", safe.Address)
	}
	if safeBalance.Balance.Cmp(st.Value) != 0 {
		return fmt.Errorf("recovery amount %d is not equal to balance %d ", st.Value, safeBalance.Balance)
	}

	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	logger.Printf("store.CountUnfinishedTransactionApprovalsForHolder(%s) => %d %v", safe.Holder, count, err)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	var extra []byte
	id := mixin.UniqueConversationID(safe.Address, st.Destination.Hex())
	switch {
	case !isHolderSigned: // Close account with safeBTC
		tx, err := node.keeperStore.ReadTransaction(ctx, hash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", hash, tx, err)
		if err != nil {
			return err
		}
		if tx == nil {
			return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
		}
		extra = uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	case isHolderSigned: // Close account with holder key
		if !ethereum.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return fmt.Errorf("ethereum.CheckTransactionPartiallySignedBy(%s, %s) holder", raw, safe.Holder)
		}
		extra = uuid.Nil.Bytes()
	}

	objectRaw := signedRaw
	rawId := mixin.UniqueConversationID(raw, raw)
	objectRaw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), objectRaw...)
	objectRaw = common.AESEncrypt(node.aesKey[:], objectRaw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(objectRaw)
	traceId := mixin.UniqueConversationID(msg, msg)
	conf := node.conf.App
	rs, err := common.CreateObjectUntilSufficient(ctx, msg, traceId, conf.ClientId, conf.SessionId, conf.PrivateKey, conf.PIN, conf.PinToken)
	logger.Printf("common.CreateObjectUntilSufficient(%v) => %v %v", msg, rs, err)
	if err != nil {
		return err
	}
	ref, err := crypto.HashFromString(rs.TransactionHash)
	if err != nil {
		return err
	}

	extra = append(extra, ref[:]...)
	action := common.ActionEthereumSafeCloseAccount
	references := []crypto.Hash{ref}
	err = node.sendKeeperResponseWithReferences(ctx, safe.Holder, byte(action), safe.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %s, %x, %v) => %v", safe.Holder, id, extra, references, err)
	if err != nil {
		return err
	}

	if isHolderSigned {
		err = node.store.FinishTransactionSignatures(ctx, hash, hex.EncodeToString(signedRaw))
		logger.Printf("store.FinishTransactionSignatures(%s, %x) => %v", hash, signedRaw, err)
		if err != nil {
			return err
		}
		return node.store.UpdateRecoveryState(ctx, safe.Address, raw, common.RequestStateDone)
	}

	err = node.store.AddTransactionPartials(ctx, hash, hex.EncodeToString(signedRaw))
	logger.Printf("store.AddTransactionPartials(%s) => %v", hash, err)
	if err != nil {
		return err
	}
	return node.store.UpdateRecoveryState(ctx, safe.Address, raw, common.RequestStatePending)
}

func (node *Node) httpApproveEthereumTransaction(ctx context.Context, raw string) error {
	logger.Printf("node.httpApproveEthereumTransaction(%s)", raw)

	rb, _ := hex.DecodeString(raw)
	st, err := ethereum.UnmarshalSafeTransaction(rb)
	if err != nil {
		return err
	}

	approval, err := node.store.ReadTransactionApproval(ctx, st.TxHash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", st.TxHash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	if ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		return nil
	}
	if !ethereum.CheckTransactionPartiallySignedBy(raw, approval.Holder) {
		return nil
	}
	tx, err := node.keeperStore.ReadTransaction(ctx, st.TxHash)
	logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", st.TxHash, tx, err)
	if err != nil || tx == nil {
		return err
	}

	err = node.store.AddTransactionPartials(ctx, st.TxHash, raw)
	logger.Printf("store.AddTransactionPartials(%s) => %v", st.TxHash, err)
	return err
}

func (node *Node) httpRevokeEthereumTransaction(ctx context.Context, txHash string, sigBase64 string) error {
	logger.Printf("node.httpRevokeEthereumTransaction(%s, %s)", txHash, sigBase64)
	approval, err := node.store.ReadTransactionApproval(ctx, txHash)
	logger.Verbosef("store.ReadTransactionApproval(%s) => %v %v", txHash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	if ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		return nil
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", txHash, tx, err)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	msg := []byte(fmt.Sprintf("REVOKE:%s:%s", tx.RequestId, tx.TransactionHash))
	err = ethereum.VerifyHashSignature(tx.Holder, msg, sig)
	logger.Printf("holder: ethereum.VerifyHashSignature(%v) => %v", tx, err)
	if err != nil {
		safe, err := node.keeperStore.ReadSafe(ctx, tx.Holder)
		if err != nil {
			return err
		}
		err = ethereum.VerifyHashSignature(safe.Observer, msg, sig)
		logger.Printf("observer: ethereum.VerifyHashSignature(%v) => %v", tx, err)
		if err != nil {
			return err
		}
	}

	id := mixin.UniqueConversationID(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionEthereumSafeRevokeTransaction
	err = node.sendKeeperResponse(ctx, tx.Holder, byte(action), approval.Chain, id, extra)
	logger.Printf("node.sendKeeperResponse(%s, %d, %s, %x)", tx.Holder, action, id, extra)
	if err != nil {
		return err
	}

	err = node.store.RevokeTransactionApproval(ctx, txHash, sigBase64+":"+approval.RawTransaction)
	logger.Printf("store.RevokeTransactionApproval(%s) => %v", txHash, err)
	return err
}
