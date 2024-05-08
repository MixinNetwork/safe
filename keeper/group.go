package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/trusted-group/mtg"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) ProcessOutput(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	_, err := node.handleBondAsset(ctx, out)
	if err != nil {
		panic(err)
	}

	req, err := node.parseRequest(out)
	logger.Printf("node.parseRequest(%v) => %v %v", out, req, err)
	if err != nil {
		return nil, ""
	}

	role := node.getActionRole(req.Action)
	if role == 0 || role != req.Role {
		return nil, ""
	}

	// FIXME this blocks the main group loop
	err = node.verifyKernelTransaction(ctx, out)
	if err != nil {
		panic(err)
	}
	err = req.VerifyFormat()
	if err != nil {
		panic(err)
	}
	err = node.store.WriteRequestIfNotExist(ctx, req)
	if err != nil {
		panic(err)
	}

	ts, asset, err := node.processRequest(ctx, req)
	logger.Printf("node.processRequest(%v) => %v %s %v", req, ts, asset, err)
	if err != nil {
		panic(err)
	}
	return ts, asset
}

func (node *Node) getActionRole(act byte) byte {
	switch act {
	case common.OperationTypeKeygenOutput:
		return common.RequestRoleSigner
	case common.OperationTypeSignOutput:
		return common.RequestRoleSigner
	case common.ActionTerminate:
		return common.RequestRoleObserver
	case common.ActionObserverAddKey:
		return common.RequestRoleObserver
	case common.ActionObserverRequestSignerKeys:
		return common.RequestRoleObserver
	case common.ActionObserverUpdateNetworkStatus:
		return common.RequestRoleObserver
	case common.ActionObserverHolderDeposit:
		return common.RequestRoleObserver
	case common.ActionObserverSetOperationParams:
		return common.RequestRoleObserver
	case common.ActionMigrateSafeToken:
		return common.RequestRoleHolder
	case common.ActionBitcoinSafeProposeAccount, common.ActionEthereumSafeProposeAccount:
		return common.RequestRoleHolder
	case common.ActionBitcoinSafeApproveAccount, common.ActionEthereumSafeApproveAccount:
		return common.RequestRoleObserver
	case common.ActionBitcoinSafeProposeTransaction, common.ActionEthereumSafeProposeTransaction:
		return common.RequestRoleHolder
	case common.ActionBitcoinSafeApproveTransaction, common.ActionEthereumSafeApproveTransaction:
		return common.RequestRoleObserver
	case common.ActionBitcoinSafeRevokeTransaction, common.ActionEthereumSafeRevokeTransaction:
		return common.RequestRoleObserver
	case common.ActionBitcoinSafeCloseAccount, common.ActionEthereumSafeCloseAccount:
		return common.RequestRoleObserver
	case common.ActionEthereumSafeRefundTransaction:
		return common.RequestRoleObserver
	default:
		return 0
	}
}

func (node *Node) handleBondAsset(ctx context.Context, out *mtg.Action) (bool, error) {
	if common.CheckTestEnvironment(ctx) {
		return false, nil
	}
	if node.checkGroupChangeTransaction(ctx, out) {
		return false, nil
	}

	meta, err := node.fetchAssetMeta(ctx, out.AssetId)
	if err != nil {
		return false, fmt.Errorf("node.fetchAssetMeta(%s) => %v", out.AssetId, err)
	}
	if meta.Chain != SafeChainPolygon {
		return false, nil
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.PolygonRPC, meta.AssetKey)
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
	spent, err := node.group.ListOutputsForAsset(ctx, node.group.GroupId, out.AssetId, math.MaxInt64, "spent", 1)
	if err != nil {
		return false, fmt.Errorf("group.ListOutputsForAsset(%s) => %v", out.AssetId, err)
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

func (node *Node) checkGroupChangeTransaction(ctx context.Context, output *mtg.Action) bool {
	g, t, m := mtg.DecodeMixinExtra(output.Extra)
	if g == "" && t == "" && m == "" {
		return false
	}
	inputs, err := node.group.ListOutputsForTransaction(ctx, output.TraceId, output.Sequence)
	if err != nil {
		panic(err)
	}
	return len(inputs) > 0
}

func (node *Node) timestamp(ctx context.Context) (uint64, error) {
	req, err := node.store.ReadLatestRequest(ctx)
	if err != nil || req == nil {
		return node.conf.MTG.Genesis.Epoch, err
	}
	return req.Sequence, nil
}

// never call this function with multiple threads, and all implementations
// should be allowed to repeat executions
// ALL failure should panic instead of continue
func (node *Node) processRequest(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
	switch req.Action {
	case common.OperationTypeKeygenOutput:
		return node.processKeyAdd(ctx, req)
	case common.OperationTypeSignOutput:
		return node.processSignerSignatureResponse(ctx, req)
	case common.ActionTerminate:
		return node.Terminate(ctx)
	case common.ActionObserverAddKey:
		return node.processKeyAdd(ctx, req)
	case common.ActionObserverRequestSignerKeys:
		return node.sendSignerKeygenRequest(ctx, req)
	case common.ActionObserverUpdateNetworkStatus:
		return node.writeNetworkInfo(ctx, req)
	case common.ActionObserverHolderDeposit:
		return node.CreateHolderDeposit(ctx, req)
	case common.ActionObserverSetOperationParams:
		return node.writeOperationParams(ctx, req)
	case common.ActionMigrateSafeToken:
		return node.processSafeTokenMigration(ctx, req)
	case common.ActionBitcoinSafeProposeAccount:
		return node.processBitcoinSafeProposeAccount(ctx, req)
	case common.ActionBitcoinSafeApproveAccount:
		return node.processBitcoinSafeApproveAccount(ctx, req)
	case common.ActionBitcoinSafeProposeTransaction:
		return node.processBitcoinSafeProposeTransaction(ctx, req)
	case common.ActionBitcoinSafeApproveTransaction:
		return node.processBitcoinSafeApproveTransaction(ctx, req)
	case common.ActionBitcoinSafeRevokeTransaction:
		return node.processSafeRevokeTransaction(ctx, req)
	case common.ActionBitcoinSafeCloseAccount:
		return node.processBitcoinSafeCloseAccount(ctx, req)
	case common.ActionEthereumSafeProposeAccount:
		return node.processEthereumSafeProposeAccount(ctx, req)
	case common.ActionEthereumSafeApproveAccount:
		return node.processEthereumSafeApproveAccount(ctx, req)
	case common.ActionEthereumSafeProposeTransaction:
		return node.processEthereumSafeProposeTransaction(ctx, req)
	case common.ActionEthereumSafeRevokeTransaction:
		return node.processSafeRevokeTransaction(ctx, req)
	case common.ActionEthereumSafeApproveTransaction:
		return node.processEthereumSafeApproveTransaction(ctx, req)
	case common.ActionEthereumSafeCloseAccount:
		return node.processEthereumSafeCloseAccount(ctx, req)
	case common.ActionEthereumSafeRefundTransaction:
		return node.processEthereumSafeRefundTransaction(ctx, req)
	default:
		panic(req.Action)
	}
}

func (node *Node) processKeyAdd(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
	old, err := node.store.ReadKey(ctx, req.Holder)
	logger.Printf("store.ReadKey(%s) => %v %v", req.Holder, old, err)
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadKey(%s) => %v %v", req.Holder, old, err)
	}
	if old != nil {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 34 {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	switch extra[0] {
	case common.RequestRoleSigner:
		if req.Role != common.RequestRoleSigner {
			return nil, "", node.store.FailRequest(ctx, req.Id)
		}
	case common.RequestRoleObserver:
		if req.Role != common.RequestRoleObserver {
			return nil, "", node.store.FailRequest(ctx, req.Id)
		}
	default:
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	chainCode, flags := extra[1:33], extra[33]
	switch flags {
	case common.RequestFlagNone:
	case common.RequestFlagCustomObserverKey:
	default:
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	switch req.Curve {
	case common.CurveSecp256k1ECDSABitcoin:
		err = bitcoin.CheckDerivation(req.Holder, chainCode, 1000)
		logger.Printf("bitcoin.CheckDerivation(%s, %x) => %v", req.Holder, chainCode, err)
		if err != nil {
			return nil, "", node.store.FailRequest(ctx, req.Id)
		}
	case common.CurveSecp256k1ECDSAEthereum, common.CurveSecp256k1ECDSAMVM, common.CurveSecp256k1ECDSAPolygon:
		err = ethereum.VerifyHolderKey(req.Holder)
		logger.Printf("ethereum.VerifyHolderKey(%s, %x) => %v", req.Holder, chainCode, err)
		if err != nil {
			return nil, "", node.store.FailRequest(ctx, req.Id)
		}
	default:
		panic(req.Curve)
	}
	return nil, "", node.store.WriteKeyFromRequest(ctx, req, int(extra[0]), chainCode, flags)
}

func (node *Node) processSignerSignatureResponse(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}
	old, err := node.store.ReadSignatureRequest(ctx, req.Id)
	logger.Printf("store.ReadSignatureRequest(%s) => %v %v", req.Id, old, err)
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadSignatureRequest(%s) => %v", req.Id, err)
	}
	if old == nil || old.State == common.RequestStateDone {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransaction(ctx, old.TransactionHash)
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadTransaction(%v) => %s %v", req, old.TransactionHash, err)
	}
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadSafe(%s) => %v", tx.Holder, err)
	}
	if safe.Signer != req.Holder {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	switch safe.Chain {
	case SafeChainBitcoin, SafeChainLitecoin:
		return node.processBitcoinSafeSignatureResponse(ctx, req, safe, tx, old)
	case SafeChainEthereum, SafeChainMVM, SafeChainPolygon:
		return node.processEthereumSafeSignatureResponse(ctx, req, safe, tx, old)
	default:
		panic(safe.Chain)
	}
}

func (node *Node) processSafeRevokeTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != chain {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 64 {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		return nil, "", fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err)
	} else if tx == nil {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	} else if tx.Holder != req.Holder {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	} else if tx.State != common.RequestStateInitial {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	txRequest, err := node.store.ReadRequest(ctx, rid.String())
	logger.Printf("store.ReadRequest(%s) => %v %v", rid.String(), txRequest, err)
	if err != nil || txRequest == nil {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}

	ms := fmt.Sprintf("REVOKE:%s:%s", rid.String(), tx.TransactionHash)
	err = node.verifySafeMessageSignatureWithHolderOrObserver(ctx, safe, ms, extra[16:])
	logger.Printf("holder: node.verifySafeMessageSignatureWithHolderOrObserver(%v) => %v", req, err)
	if err != nil {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}

	meta, err := node.fetchAssetMeta(ctx, txRequest.AssetId)
	logger.Printf("node.fetchAssetMeta(%s) => %v %v", txRequest.AssetId, meta, err)
	if err != nil {
		return nil, "", fmt.Errorf("node.fetchAssetMeta(%s) => %v", txRequest.AssetId, err)
	}
	if common.CheckTestEnvironment(ctx) {
		meta.Chain = SafeChainPolygon
	}
	if meta.Chain != SafeChainPolygon {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	t, asset, err := node.buildTransaction(ctx, req.Sequence, meta.AssetId, safe.Receivers, int(safe.Threshold), txRequest.Amount.String(), []byte("refund"), req.Id)
	if err != nil || asset != "" {
		return nil, asset, err
	}

	err = node.store.RevokeTransactionWithRequest(ctx, tx, safe, req)
	if err != nil {
		return nil, "", err
	}

	return []*mtg.Transaction{t}, "", nil
}

func (node *Node) processSafeTokenMigration(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string, error) {
	meta, err := node.fetchAssetMeta(ctx, req.AssetId)
	if err != nil {
		return nil, "", fmt.Errorf("node.fetchAssetMeta(%s) => %v", req.AssetId, err)
	}
	if meta.Chain != SafeChainPolygon {
		logger.Printf("invalid meta asset chain: %d", meta.Chain)
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	deployed, err := abi.CheckFactoryAssetDeployed(node.conf.PolygonRPC, meta.AssetKey)
	logger.Printf("abi.CheckFactoryAssetDeployed(%s) => %v %v", meta.AssetKey, deployed, err)
	if err != nil {
		return nil, "", fmt.Errorf("abi.CheckFactoryAssetDeployed(%s) => %v", meta.AssetKey, err)
	}
	if deployed.Sign() <= 0 {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}

	id := uuid.Must(uuid.FromBytes(deployed.Bytes()))
	_, err = node.fetchAssetMeta(ctx, id.String())
	if err != nil {
		return nil, "", fmt.Errorf("node.fetchAssetMeta(%s) => %v", id, err)
	}
	if !common.CheckTestEnvironment(ctx) {
		spent, err := node.group.ListOutputsForAsset(ctx, node.group.GroupId, req.AssetId, math.MaxInt64, "spent", 1)
		logger.Printf("group.ListOutputsForAsset(%s) => %d %v", req.AssetId, len(spent), err)
		if err != nil {
			return nil, "", fmt.Errorf("group.ListOutputsForAsset(%s) => %v", req.AssetId, err)
		}
		if len(spent) > 0 {
			return nil, "", node.store.FailRequest(ctx, req.Id)
		}
	}

	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 20 {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	receiver := gc.BytesToAddress(extra).String()

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", req.Holder, safe, err)
	if err != nil {
		return nil, "", err
	}
	if safe == nil || safe.State != common.RequestStateDone {
		return nil, "", node.store.FailRequest(ctx, req.Id)
	}
	err = node.store.MigrateSafeWithRequest(ctx, receiver, req, safe)
	logger.Printf("store.MigrateSafeWithRequest(%s %s) => %v", receiver, safe.Holder, err)

	return nil, "", err
}
