package keeper

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
)

func (node *Node) ProcessOutput(ctx context.Context, out *mtg.Output) {
	_, err := node.handleBondAsset(ctx, out)
	if err != nil {
		panic(err)
	}

	req, err := node.parseRequest(out)
	logger.Printf("node.parseRequest(%v) => %v %v", out, req, err)
	if err != nil {
		return
	}

	switch req.Action {
	case common.OperationTypeKeygenOutput:
	case common.OperationTypeSignOutput:
	case common.ActionObserverAddKey:
	case common.ActionObserverRequestSignerKeys:
	case common.ActionObserverUpdateNetworkStatus:
	case common.ActionObserverHolderDeposit:
	case common.ActionObserverAccountantDepost:
	case common.ActionObserverSetAccountPlan:
	case common.ActionBitcoinSafeProposeAccount:
	case common.ActionBitcoinSafeApproveAccount:
	case common.ActionBitcoinSafeProposeTransaction:
	case common.ActionBitcoinSafeApproveTransaction:
	default:
		return
	}
	role := node.getActionRole(req.Action)
	if role == 0 || role != req.Role {
		return
	}

	err = node.verifyKernelTransaction(ctx, out)
	if err != nil {
		panic(err)
	}
	err = node.store.WriteRequestIfNotExist(ctx, req)
	if err != nil {
		panic(err)
	}
}

func (node *Node) getActionRole(act byte) byte {
	switch act {
	case common.OperationTypeKeygenOutput:
		return common.RequestRoleSigner
	case common.OperationTypeSignOutput:
		return common.RequestRoleSigner
	case common.ActionObserverAddKey:
		return common.RequestRoleObserver
	case common.ActionObserverRequestSignerKeys:
		return common.RequestRoleObserver
	case common.ActionObserverUpdateNetworkStatus:
		return common.RequestRoleObserver
	case common.ActionObserverHolderDeposit:
		return common.RequestRoleObserver
	case common.ActionObserverAccountantDepost:
		return common.RequestRoleObserver
	case common.ActionObserverSetAccountPlan:
		return common.RequestRoleObserver
	case common.ActionBitcoinSafeProposeAccount:
		return common.RequestRoleHolder
	case common.ActionBitcoinSafeApproveAccount:
		return common.RequestRoleObserver
	case common.ActionBitcoinSafeProposeTransaction:
		return common.RequestRoleHolder
	case common.ActionBitcoinSafeApproveTransaction:
		return common.RequestRoleObserver
	default:
		return 0
	}
}

func (node *Node) ProcessCollectibleOutput(context.Context, *mtg.CollectibleOutput) {}

func (node *Node) handleBondAsset(ctx context.Context, out *mtg.Output) (bool, error) {
	if common.CheckTestEnvironment(ctx) {
		return false, nil
	}
	if node.checkGroupChangeTransaction(out.Memo) {
		return false, nil
	}

	meta, err := node.fetchAssetMeta(ctx, out.AssetID)
	if err != nil {
		return false, fmt.Errorf("node.fetchAssetMeta(%s) => %v", out.AssetID, err)
	}
	if meta.Chain != SafeChainMVM {
		return false, nil
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.MVMRPC, meta.AssetKey)
	logger.Verbosef("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil {
		return false, fmt.Errorf("abi.CheckFactoryAssetDeployed(%s) => %v", meta.AssetKey, err)
	}
	if deployed.Sign() <= 0 {
		return false, nil
	}

	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))
	asset, err := node.fetchAssetMeta(ctx, id.String())
	if err != nil {
		return false, fmt.Errorf("node.fetchAssetMeta(%s) => %v", id, err)
	}
	spent, err := node.group.ListOutputsForAsset("", out.AssetID, "spent", 1)
	if err != nil {
		return false, fmt.Errorf("group.ListOutputsForAsset(%s) => %v", out.AssetID, err)
	}
	if len(spent) > 0 {
		return false, nil
	}

	max := node.bondMaxSupply(ctx, asset.Chain, asset.AssetId)
	if !out.Amount.Equal(max) {
		return false, fmt.Errorf("node.handleBondAsset(%s) => %s", id, out.Amount)
	}
	err = node.verifyKernelTransaction(ctx, out)
	if err != nil {
		panic(err)
	}
	return true, nil
}

func (node *Node) checkGroupChangeTransaction(memo string) bool {
	msp := mtg.DecodeMixinExtra(memo)
	if msp == nil {
		return false
	}
	inputs, err := node.group.ListOutputsForTransaction(msp.T.String())
	if err != nil {
		panic(err)
	}
	return len(inputs) > 0
}

func (node *Node) loopProcessRequests(ctx context.Context) {
	for {
		req, err := node.store.ReadPendingRequest(ctx)
		if err != nil {
			panic(err)
		}
		if req == nil {
			time.Sleep(time.Second)
			continue
		}
		err = req.VerifyFormat()
		if err != nil {
			panic(err)
		}
		err = node.processRequest(ctx, req)
		logger.Printf("node.processRequest(%v) => %v", req, err)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) timestamp(ctx context.Context) (time.Time, error) {
	req, err := node.store.ReadLatestRequest(ctx)
	if err != nil || req == nil {
		return time.Unix(0, node.conf.MTG.Genesis.Timestamp), err
	}
	return req.CreatedAt, nil
}

// never call this function with multiple threads, and all implementations
// should be allowed to repeat executions
// ALL failure should panic instead of continue
func (node *Node) processRequest(ctx context.Context, req *common.Request) error {
	switch req.Action {
	case common.OperationTypeKeygenOutput:
		return node.processKeyAdd(ctx, req)
	case common.OperationTypeSignOutput:
		return node.processSignatureResponse(ctx, req)
	case common.ActionObserverAddKey:
		return node.processKeyAdd(ctx, req)
	case common.ActionObserverRequestSignerKeys:
		return node.sendSignerKeygenRequest(ctx, req)
	case common.ActionObserverUpdateNetworkStatus:
		return node.writeNetworkInfo(ctx, req)
	case common.ActionObserverHolderDeposit:
		return node.CreateHolderDeposit(ctx, req)
	case common.ActionObserverAccountantDepost:
		return node.CreateAccountantDeposit(ctx, req)
	case common.ActionObserverSetAccountPlan:
		return node.writeAccountPlan(ctx, req)
	case common.ActionBitcoinSafeProposeAccount:
		return node.processBitcoinSafeProposeAccount(ctx, req)
	case common.ActionBitcoinSafeApproveAccount:
		return node.processBitcoinSafeApproveAccount(ctx, req)
	case common.ActionBitcoinSafeProposeTransaction:
		return node.processBitcoinSafeProposeTransaction(ctx, req)
	case common.ActionBitcoinSafeApproveTransaction:
		return node.processBitcoinSafeApproveTransaction(ctx, req)
	default:
		panic(req.Action)
	}
}

func (node *Node) processKeyAdd(ctx context.Context, req *common.Request) error {
	old, err := node.store.ReadKey(ctx, req.Holder)
	logger.Printf("store.ReadKey(%s) => %v %v", req.Holder, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadKey(%s) => %v %v", req.Holder, old, err)
	}
	if old != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 1 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	switch extra[0] {
	case common.RequestRoleSigner:
		if req.Role != common.RequestRoleSigner {
			return node.store.FinishRequest(ctx, req.Id)
		}
	case common.RequestRoleObserver:
		if req.Role != common.RequestRoleObserver {
			return node.store.FinishRequest(ctx, req.Id)
		}
	case common.RequestRoleAccountant:
		if req.Role != common.RequestRoleObserver {
			return node.store.FinishRequest(ctx, req.Id)
		}
	default:
		return node.store.FinishRequest(ctx, req.Id)
	}
	return node.store.WriteKeyFromRequest(ctx, req, int(extra[0]))
}

func (node *Node) processSignatureResponse(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}
	old, err := node.store.ReadSignatureRequest(ctx, req.Id)
	logger.Printf("store.ReadSignatureRequest(%s) => %v %v", req.Id, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadSignatureRequest(%s) => %v", req.Id, err)
	}
	if old == nil || old.State == common.RequestStateDone || old.CreatedAt.Add(SafeSignatureTimeout).Before(req.CreatedAt) {
		return node.store.FinishRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransaction(ctx, old.TransactionHash)
	if err != nil {
		return fmt.Errorf("store.ReadTransaction(%v) => %s %v", req, old.TransactionHash, err)
	}
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", tx.Holder, err)
	}
	if safe.Signer != req.Holder {
		return node.store.FinishRequest(ctx, req.Id)
	}

	sig, _ := hex.DecodeString(req.Extra)
	msg := common.DecodeHexOrPanic(old.Message)
	err = bitcoin.VerifySignatureDER(safe.Signer, msg, sig)
	logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", req, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	err = node.store.FinishSignatureRequest(ctx, req)
	logger.Printf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	if err != nil {
		return fmt.Errorf("store.FinishSignatureRequest(%s) => %v", req.Id, err)
	}

	b := common.DecodeHexOrPanic(tx.RawTransaction)
	spsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := spsbt.Packet.UnsignedTx

	requests, err := node.store.ListAllSignaturesForTransaction(ctx, old.TransactionHash, common.RequestStatePending)
	logger.Printf("store.ListAllSignaturesForTransaction(%s) => %d %v", old.TransactionHash, len(requests), err)
	if err != nil {
		return fmt.Errorf("store.ListAllSignaturesForTransaction(%s) => %v", old.TransactionHash, err)
	}

	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if !required {
			continue
		}

		sr := requests[idx]
		if sr == nil {
			return node.store.FinishRequest(ctx, req.Id)
		}
		hash := spsbt.SigHash(idx)
		msg := common.DecodeHexOrPanic(sr.Message)
		if !bytes.Equal(hash, msg) {
			panic(sr.Message)
		}
		sig := common.DecodeHexOrPanic(sr.Signature.String)
		err = bitcoin.VerifySignatureDER(safe.Signer, hash, sig)
		if err != nil {
			panic(sr.Signature.String)
		}
		spsbt.Packet.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
			PubKey:    common.DecodeHexOrPanic(safe.Signer),
			Signature: sig,
		}}
	}

	exk := node.writeToMVMOrPanic(ctx, spsbt.Marshal())
	id := mixin.UniqueConversationID(old.TransactionHash, hex.EncodeToString(exk))
	err = node.sendObserverResponse(ctx, id, common.ActionBitcoinSafeApproveTransaction, exk)
	if err != nil {
		return fmt.Errorf("node.sendObserverResponse(%s, %x) => %v", id, exk, err)
	}
	raw := hex.EncodeToString(spsbt.Marshal())
	return node.store.FinishTransactionSignaturesWithRequest(ctx, old.TransactionHash, raw, req, int64(len(msgTx.TxIn)))
}
