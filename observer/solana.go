package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	sg "github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func (node *Node) solanaClient() *solana.Client {
	rpc := node.conf.SolanaRPC
	ws := node.conf.SolanaWS
	return solana.NewClient(rpc, ws)
}

func (node *Node) solanaNetworkInfoLoop(ctx context.Context) {
	client := node.solanaClient()
	chain := byte(common.SafeChainSolana)

	for {
		time.Sleep(depositNetworkInfoDelay)

		height, blockHash, err := client.RPCGetBlockHeight(ctx)
		if err != nil {
			logger.Printf("solana.RPCGetBlockHeight => %v", err)
			continue
		}

		delay := node.getChainFinalizationDelay(chain)
		if delay > height || delay < 1 {
			panic(delay)
		}
		height = int64(height) + 1 - delay
		info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, chain, time.Now())
		if err != nil {
			panic(err)
		}
		if info != nil && info.Height > uint64(height) {
			logger.Printf("node.keeperStore.ReadLatestNetworkInfo(%d) => %v %d", chain, info, height)
			continue
		}

		unitPrice, err := client.RPCGetUnitPrice(ctx)
		if err != nil {
			logger.Printf("solana.RPCGetUnitPrice => %v", err)
			continue
		}

		extra := []byte{chain}
		extra = binary.BigEndian.AppendUint64(extra, uint64(height))
		extra = append(extra, blockHash[:]...)
		id := common.UniqueId(common.SafeSolanaChainId, fmt.Sprintf("%s:%d", blockHash, height))
		id = common.UniqueId(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), unitPrice))
		logger.Printf("node.ethereumNetworkInfoLoop(%d) => %d %d %s %s", chain, height, unitPrice, blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendKeeperResponse(ctx, dummy, byte(action), chain, id, extra)
		logger.Verbosef("node.sendKeeperResponse(%d, %s, %x) => %v", chain, id, extra, err)
	}
}

func (node *Node) solanaRPCBlocksLoop(ctx context.Context) {
	client := node.solanaClient()

	for {
		checkpoint, err := node.readDepositCheckpoint(ctx, common.SafeChainSolana)
		if err != nil {
			panic(err)
		}
		height, _, err := client.RPCGetBlockHeight(ctx)
		if err != nil {
			logger.Printf("solana.RPCGetBlockHeight => %v", err)
			time.Sleep(time.Second * 5)
			continue
		}
		logger.Printf("node.solanaReadDepositCheckpoint(%d) => %d %d", common.SafeChainSolana, checkpoint, height)
		delay := node.getChainFinalizationDelay(common.SafeChainSolana)
		if checkpoint+delay > height+1 {
			time.Sleep(time.Second * 5)
			continue
		}
		err = node.solanaReadBlock(ctx, checkpoint)
		logger.Printf("node.solanaReadBlock(%d, %d) => %v", common.SafeChainSolana, checkpoint, err)
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}

		err = node.solanaWriteDepositCheckpoint(ctx, checkpoint+1)
		if err != nil {
			panic(err)
		}
	}

}

func (node *Node) solanaReadBlock(ctx context.Context, checkpoint int64) error {
	client := node.solanaClient()
	block, err := client.RPCGetBlockByHeight(ctx, uint64(checkpoint))
	if err != nil || block == nil {
		return err
	}

	for _, tx := range block.Transactions {
		transfers, err := client.ExtractTransfersFromTransaction(ctx, tx.MustGetTransaction(), tx.Meta)
		if err != nil {
			return err
		}

		if err := node.solanaProcessTransfers(ctx, *block.BlockHeight, transfers); err != nil {
			return err
		}
	}

	return nil
}

func (node *Node) parseSolanaBlockBalanceChanges(ctx context.Context, transfers []*solana.Transfer) (map[string]*big.Int, error) {
	changes := make(map[string]*big.Int)
	for _, t := range transfers {
		if t.Receiver == solana.SolanaEmptyAddress {
			continue
		}

		safe, err := node.keeperStore.ReadSafeByAddress(ctx, t.Receiver)
		logger.Verbosef("keeperStore.ReadSafeByAddress(%s) => %v %v", t.Receiver, safe, err)
		if err != nil {
			return nil, err
		} else if safe == nil || safe.Chain != common.SafeChainSolana {
			continue
		}

		old, err := node.keeperStore.ReadDeposit(ctx, t.Signature, t.Index)
		logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", t.Signature, t.Index, t.AssetId, t.Receiver, old, err)
		if err != nil {
			return nil, err
		} else if old != nil {
			continue
		}

		key := fmt.Sprintf("%s:%s", t.Receiver, t.TokenAddress)
		total := changes[key]
		if total != nil {
			changes[key] = new(big.Int).Add(total, t.Value)
		} else {
			changes[key] = t.Value
		}
	}
	return changes, nil
}

func (node *Node) solanaProcessTransfers(ctx context.Context, height uint64, transfers []*solana.Transfer) error {
	changes, err := node.parseSolanaBlockBalanceChanges(ctx, transfers)
	logger.Printf("node.parseSolanaBlockBalanceChanges(%d, %d, %d) => %d %v", common.SafeChainSolana, height, len(transfers), len(changes), err)
	if err != nil || len(changes) == 0 {
		return err
	}

	for _, transfer := range transfers {
		key := fmt.Sprintf("%s:%s", transfer.Receiver, transfer.TokenAddress)
		if _, ok := changes[key]; !ok {
			continue
		}
		err := node.solanaWritePendingDeposit(ctx, transfer)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (node *Node) solanaWriteDepositCheckpoint(ctx context.Context, checkpoint int64) error {
	return node.store.WriteProperty(ctx, depositCheckpointKey(common.SafeChainSolana), fmt.Sprint(checkpoint))
}

func (node *Node) solanaWritePendingDeposit(ctx context.Context, transfer *solana.Transfer) error {
	old, err := node.keeperStore.ReadDeposit(ctx, transfer.Signature, transfer.Index)
	logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", transfer.Signature, transfer.Index, transfer.AssetId, transfer.Receiver, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", transfer.Signature, transfer.Index, transfer.AssetId, transfer.Receiver, old, err)
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

	asset, err := node.fetchAssetMeta(ctx, transfer.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", transfer.AssetId, asset, err)
	if err != nil || asset == nil {
		return err
	}

	_, err = node.checkOrDeployKeeperBond(ctx, safe.Chain, transfer.AssetId, transfer.TokenAddress, safe.Holder, safe.Address)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", safe.Holder, err)
	}

	var amount decimal.Decimal
	switch transfer.AssetId {
	case common.SafeSolanaChainId:
		amount = decimal.NewFromBigInt(transfer.Value, -int32(solana.NativeTokenDecimals))
	default:
		client := node.solanaClient()
		asset, err := client.RPCGetAsset(ctx, transfer.TokenAddress)
		if err != nil {
			return err
		}
		amount = decimal.NewFromBigInt(transfer.Value, -int32(asset.Decimals))
	}

	id := common.UniqueId(transfer.AssetId, safe.Holder)
	id = common.UniqueId(id, fmt.Sprintf("%s:%d", transfer.Signature, transfer.Index))
	createdAt := time.Now().UTC()
	deposit := &Deposit{
		TransactionHash: transfer.Signature,
		OutputIndex:     transfer.Index,
		AssetId:         transfer.AssetId,
		AssetAddress:    transfer.TokenAddress,
		Amount:          amount.String(),
		Receiver:        transfer.Receiver,
		Sender:          transfer.Sender,
		Holder:          safe.Holder,
		Category:        common.ActionObserverHolderDeposit,
		State:           common.RequestStateInitial,
		Chain:           common.SafeChainSolana,
		RequestId:       id,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}

	err = node.store.WritePendingDepositIfNotExists(ctx, deposit)
	if err != nil {
		return fmt.Errorf("store.WritePendingDeposit(%v) => %v", deposit, err)
	}
	return nil
}

func (node *Node) solanaDepositConfirmLoop(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		deposits, err := node.store.ListDeposits(ctx, common.SafeChainSolana, "", common.RequestStateInitial, 0)
		if err != nil {
			panic(err)
		}
		for _, d := range deposits {
			err := node.solanaConfirmPendingDeposit(ctx, d)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) solanaConfirmPendingDeposit(ctx context.Context, deposit *Deposit) error {
	client := node.solanaClient()

	asset, err := node.store.ReadAssetMeta(ctx, deposit.AssetId)
	if err != nil || asset == nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, deposit.Holder)
	if err != nil || safe == nil {
		return err
	}
	bonded, err := node.checkOrDeployKeeperBond(ctx, deposit.Chain, deposit.AssetId, asset.AssetKey, deposit.Holder, safe.Address)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}

	decimals := int32(solana.NativeTokenDecimals)
	switch asset.AssetId {
	case common.SafeSolanaChainId:
	default:
		decimals = int32(asset.Decimals)
	}

	info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, deposit.Chain, time.Now())
	if err != nil {
		return fmt.Errorf("keeperStore.ReadLatestNetworkInfo(%d) => %v", deposit.Chain, err)
	} else if info == nil {
		return nil
	}
	if info.CreatedAt.After(time.Now()) {
		panic(fmt.Errorf("malicious solana network info %v", info))
	}

	match, tx, err := client.VerifyDeposit(ctx, deposit.TransactionHash, deposit.AssetAddress, deposit.Receiver, deposit.OutputIndex, ethereum.ParseAmount(deposit.Amount, decimals))
	if err != nil {
		panic(err)
	}
	if match == nil {
		panic(fmt.Errorf("malicious solana deposit %s", deposit.TransactionHash))
	}

	isSafe, err := node.checkTrustedSender(ctx, deposit.Sender)
	if err != nil {
		return fmt.Errorf("node.checkTrustedSender(%s) => %v", deposit.Sender, err)
	}
	confirmations := info.Height - tx.Slot + 1
	if info.Height < tx.Slot {
		confirmations = 0
	}
	if isSafe && confirmations > 0 {
		confirmations = 1000000
	}
	if !ethereum.CheckFinalization(confirmations, deposit.Chain) {
		return nil
	}

	return node.sendKeeperDepositTransaction(ctx, deposit, int32(asset.Decimals))
}

func (node *Node) solanaTransactionApprovalLoop(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		approvals, err := node.store.ListPendingTransactionApprovals(ctx, common.SafeChainSolana)
		if err != nil {
			panic(err)
		}

		for _, approval := range approvals {
			err := node.sendToKeeperSolanaApproveTransaction(ctx, approval)
			logger.Verbosef("node.sendToKeeperSolanaApproveTransaction(%v) => %v", approval, err)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) sendToKeeperSolanaApproveTransaction(ctx context.Context, approval *Transaction) error {
	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	if err != nil {
		return err
	}

	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	tx, err := sg.TransactionFromBytes(raw)
	if err != nil {
		panic(approval.RawTransaction)
	}

	if solana.CheckTransactionSignedBy(tx, sg.MPK(safe.Observer)) {
		return node.sendToKeeperSolanaApproveRecoveryTransaction(ctx, approval)
	}
	return node.sendToKeeperSolanaApproveNormalTransaction(ctx, approval)
}

func (node *Node) sendToKeeperSolanaApproveRecoveryTransaction(ctx context.Context, approval *Transaction) error {
	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	stx, err := sg.TransactionFromBytes(raw)
	logger.Printf("sg.TransactionFromBytes(%s) => %v %v", approval.RawTransaction, stx, err)
	if err != nil {
		panic(approval.RawTransaction)
	}

	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	logger.Printf("keeperStore.ReadSafe(%s) => %v %v", approval.Holder, safe, err)
	if err != nil {
		return err
	}

	signedByHolder := solana.CheckTransactionSignedBy(stx, sg.MPK(safe.Holder))

	var extra []byte
	switch {
	case signedByHolder:
		extra = uuid.Nil.Bytes()
	default:
		signed, err := node.solanaCheckKeeperSignedTransaction(ctx, approval)
		logger.Printf("node.solanaCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
		if err != nil || signed {
			return err
		}

		tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
		if err != nil {
			return err
		}
		extra = uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	}

	objectRaw := raw
	rawId := common.UniqueId(approval.RawTransaction, approval.RawTransaction)
	objectRaw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), objectRaw...)
	objectRaw = common.AESEncrypt(node.aesKey[:], objectRaw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(objectRaw)
	traceId := common.UniqueId(msg, msg)
	ref, err := common.WriteStorageUntilSufficient(ctx, node.mixin, objectRaw, traceId, node.safeUser())
	logger.Printf("common.CreateObjectUntilSufficient(%v) => %s %v", msg, ref, err)
	if err != nil {
		return err
	}

	destination, err := solanaExtractTransactionDestination(stx)
	if err != nil {
		panic(err)
	}

	id := common.UniqueId(safe.Address, destination.String())
	extra = append(extra, ref[:]...)
	action := common.ActionSolanaSafeCloseAccount
	references := []crypto.Hash{ref}
	err = node.sendKeeperResponseWithReferences(ctx, safe.Holder, byte(action), safe.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %s, %x, %v) => %v", safe.Holder, id, extra, references, err)
	if err != nil {
		return err
	}

	if approval.UpdatedAt.Add(keeper.SafeSignatureTimeout).After(time.Now()) {
		return nil
	}
	id = common.UniqueId(id, approval.UpdatedAt.String())
	err = node.sendKeeperResponseWithReferences(ctx, safe.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", safe.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}
	return node.store.UpdateTransactionApprovalRequestTime(ctx, approval.TransactionHash)
}

func solanaExtractTransactionDestination(tx *sg.Transaction) (sg.PublicKey, error) {
	outputs := solana.ExtractOutputs(tx)
	if len(outputs) == 0 {
		return sg.PublicKey{}, fmt.Errorf("no outputs found")
	}

	destination := outputs[0].Destination
	for _, o := range outputs {
		if o.Destination != destination {
			return sg.PublicKey{}, fmt.Errorf("multiple destinations found")
		}
	}

	return sg.PublicKeyFromBase58(destination)
}

func (node *Node) sendToKeeperSolanaApproveNormalTransaction(ctx context.Context, approval *Transaction) error {
	signed, err := node.solanaCheckKeeperSignedTransaction(ctx, approval)
	logger.Printf("node.solanaCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
	if err != nil || signed {
		return err
	}

	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	stx, err := sg.TransactionFromBytes(raw)
	if err != nil {
		panic(approval.RawTransaction)
	}

	// transaction must be signed by the holder
	if !solana.CheckTransactionSignedBy(stx, sg.MPK(approval.Holder)) {
		panic(approval.RawTransaction)
	}

	rawId := common.UniqueId(approval.RawTransaction, approval.RawTransaction)
	raw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), raw...)
	raw = common.AESEncrypt(node.aesKey[:], raw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(raw)
	traceId := common.UniqueId(msg, msg)
	ref, err := common.WriteStorageUntilSufficient(ctx, node.mixin, raw, traceId, node.safeUser())
	logger.Printf("WriteStorageUntilSufficient(%s) => %s %v", traceId, ref, err)
	if err != nil {
		return err
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
	if err != nil {
		return err
	}
	id := common.UniqueId(approval.TransactionHash, approval.TransactionHash)
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
	id = common.UniqueId(id, approval.UpdatedAt.String())
	err = node.sendKeeperResponseWithReferences(ctx, tx.Holder, byte(action), approval.Chain, id, extra, references)
	logger.Printf("node.sendKeeperResponseWithReferences(%s, %d, %s, %x, %s)", tx.Holder, action, id, extra, ref)
	if err != nil {
		return err
	}
	return node.store.UpdateTransactionApprovalRequestTime(ctx, approval.TransactionHash)
}

func (node *Node) solanaCheckKeeperSignedTransaction(ctx context.Context, approval *Transaction) (bool, error) {
	requests, err := node.keeperStore.ListAllSignaturesForTransaction(ctx, approval.TransactionHash, common.RequestStateDone)
	if err != nil {
		return false, err
	}
	if len(requests) != 1 {
		return false, err
	}
	sig := common.DecodeHexOrPanic(requests[0].Signature.String)
	if len(sig) < sg.SignatureLength {
		return false, nil
	}
	return true, nil
}

func (node *Node) solanaTransactionSpentLoop(ctx context.Context) {
	client := node.solanaClient()

	for {
		time.Sleep(3 * time.Second)
		txs, err := node.store.ListFullySignedTransactionApprovals(ctx, common.SafeChainSolana)
		if err != nil {
			panic(err)
		}

		for _, tx := range txs {
			raw := common.DecodeHexOrPanic(tx.RawTransaction)
			stx, err := sg.TransactionFromBytes(raw)
			if err != nil {
				panic(tx.RawTransaction)
			}

			sig, err := client.SendTransaction(ctx, stx)
			if err != nil {
				panic(err)
			}

			if err := node.store.ConfirmFullySignedTransactionApproval(ctx, tx.TransactionHash, sig, tx.RawTransaction); err != nil {
				panic(err)
			}

			etx, err := client.RPCGetTransaction(ctx, sig)
			if err != nil || etx == nil || etx.Slot == 0 {
				panic(fmt.Errorf("solana.RPCGetTransaction(%s) => %v %v", sig, etx, err))
			}

			transfers, err := client.ExtractTransfersFromTransaction(ctx, common.Must(etx.Transaction.GetTransaction()), etx.Meta)
			if err != nil {
				panic(err)
			}

			if err := node.solanaProcessTransfers(ctx, etx.Slot, transfers); err != nil {
				panic(err)
			}
		}
	}
}
