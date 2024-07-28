package keeper

import (
	"context"
	"fmt"
	"math"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) ProcessOutput(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	// FIXME we can remove these extra checks when we use group.Run
	txs1, asset1 := node.processAction(ctx, out)
	txs2, asset2 := node.processAction(ctx, out)
	mtg.ReplayCheck(out, txs1, txs2, asset1, asset2)
	return txs1, asset1
}

func (node *Node) processAction(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	isDeposit := node.verifyKernelTransaction(ctx, out)
	if isDeposit {
		return nil, ""
	}

	_, err := node.handleBondAsset(ctx, out)
	if err != nil {
		panic(err)
	}

	req, err := node.parseRequest(out)
	logger.Printf("node.parseRequest(%v) => %v %v", out, req, err)
	if err != nil {
		return nil, ""
	}

	rtxs, err := node.store.ReadRequestTransactions(ctx, req.Id)
	if err != nil {
		panic(err)
	}
	if rtxs != nil {
		return rtxs.Transactions, rtxs.Compaction
	}

	role := node.getActionRole(req.Action)
	if role == 0 || role != req.Role {
		return nil, ""
	}

	err = req.VerifyFormat()
	if err != nil {
		panic(err)
	}
	err = node.store.WriteRequestIfNotExist(ctx, req)
	if err != nil {
		panic(err)
	}

	txs, asset := node.processRequest(ctx, req)
	logger.Printf("node.processRequest(%v) => %v %s", req, txs, asset)
	return txs, asset
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

	meta, err := node.fetchAssetMeta(ctx, out.AssetId)
	if err != nil {
		return false, fmt.Errorf("node.fetchAssetMeta(%s) => %v", out.AssetId, err)
	}
	if meta.Chain != common.SafeChainPolygon {
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
	_, err = node.fetchAssetMeta(ctx, id.String())
	if err != nil {
		return false, fmt.Errorf("node.fetchAssetMeta(%s) => %v", id, err)
	}
	spent := node.group.ListOutputsForAsset(ctx, node.conf.AppId, out.AssetId, math.MaxInt64, "spent", 1)
	if len(spent) > 0 {
		return false, nil
	}

	return true, nil
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
func (node *Node) processRequest(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
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
		return node.processSignerKeygenRequests(ctx, req)
	case common.ActionObserverUpdateNetworkStatus:
		return node.writeNetworkInfo(ctx, req)
	case common.ActionObserverHolderDeposit:
		return node.CreateHolderDeposit(ctx, req)
	case common.ActionObserverSetOperationParams:
		return node.writeOperationParams(ctx, req)
	case common.ActionMigrateSafeToken:
		return node.checkSafeTokenMigration(ctx, req)
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

func (node *Node) processKeyAdd(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	old, err := node.store.ReadKey(ctx, req.Holder)
	logger.Printf("store.ReadKey(%s) => %v %v", req.Holder, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadKey(%s) => %v %v", req.Holder, old, err))
	}
	if old != nil {
		return node.failRequest(ctx, req, "")
	}
	extra := req.ExtraBytes()
	if len(extra) != 34 {
		return node.failRequest(ctx, req, "")
	}
	switch extra[0] {
	case common.RequestRoleSigner:
		if req.Role != common.RequestRoleSigner {
			return node.failRequest(ctx, req, "")
		}
	case common.RequestRoleObserver:
		if req.Role != common.RequestRoleObserver {
			return node.failRequest(ctx, req, "")
		}
	default:
		return node.failRequest(ctx, req, "")
	}
	chainCode, flags := extra[1:33], extra[33]
	switch flags {
	case common.RequestFlagNone:
	case common.RequestFlagCustomObserverKey:
	default:
		return node.failRequest(ctx, req, "")
	}
	switch req.Curve {
	case common.CurveSecp256k1ECDSABitcoin:
		err = bitcoin.CheckDerivation(req.Holder, chainCode, 1000)
		logger.Printf("bitcoin.CheckDerivation(%s, %x) => %v", req.Holder, chainCode, err)
		if err != nil {
			return node.failRequest(ctx, req, "")
		}
	case common.CurveSecp256k1ECDSAEthereum, common.CurveSecp256k1ECDSAMVM, common.CurveSecp256k1ECDSAPolygon:
		err = ethereum.VerifyHolderKey(req.Holder)
		logger.Printf("ethereum.VerifyHolderKey(%s, %x) => %v", req.Holder, chainCode, err)
		if err != nil {
			return node.failRequest(ctx, req, "")
		}
	default:
		panic(req.Curve)
	}
	err = node.store.WriteKeyFromRequest(ctx, req, int(extra[0]), chainCode, flags)
	if err != nil {
		panic(err)
	}
	return nil, ""
}

func (node *Node) processSignerSignatureResponse(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleSigner {
		panic(req.Role)
	}
	old, err := node.store.ReadSignatureRequest(ctx, req.Id)
	logger.Printf("store.ReadSignatureRequest(%s) => %v %v", req.Id, old, err)
	if err != nil {
		panic(fmt.Errorf("store.ReadSignatureRequest(%s) => %v", req.Id, err))
	}
	if old == nil || old.State == common.RequestStateDone {
		return node.failRequest(ctx, req, "")
	}
	tx, err := node.store.ReadTransaction(ctx, old.TransactionHash)
	if err != nil {
		panic(fmt.Errorf("store.ReadTransaction(%v) => %s %v", req, old.TransactionHash, err))
	}
	safe, err := node.store.ReadSafe(ctx, tx.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", tx.Holder, err))
	}
	if safe.Signer != req.Holder {
		return node.failRequest(ctx, req, "")
	}
	switch safe.Chain {
	case common.SafeChainBitcoin, common.SafeChainLitecoin:
		return node.processBitcoinSafeSignatureResponse(ctx, req, safe, tx, old)
	case common.SafeChainEthereum, common.SafeChainPolygon:
		return node.processEthereumSafeSignatureResponse(ctx, req, safe, tx, old)
	default:
		panic(safe.Chain)
	}
}

func (node *Node) processSafeRevokeTransaction(ctx context.Context, req *common.Request) ([]*mtg.Transaction, string) {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	chain := common.SafeCurveChain(req.Curve)
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		panic(fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err))
	}
	if safe == nil || safe.Chain != chain {
		return node.failRequest(ctx, req, "")
	}

	extra := req.ExtraBytes()
	if len(extra) < 64 {
		return node.failRequest(ctx, req, "")
	}
	rid, err := uuid.FromBytes(extra[:16])
	if err != nil {
		return node.failRequest(ctx, req, "")
	}
	tx, err := node.store.ReadTransactionByRequestId(ctx, rid.String())
	if err != nil {
		panic(fmt.Errorf("store.ReadTransactionByRequestId(%v) => %s %v", req, rid.String(), err))
	} else if tx == nil {
		return node.failRequest(ctx, req, "")
	} else if tx.Holder != req.Holder {
		return node.failRequest(ctx, req, "")
	} else if tx.State != common.RequestStateInitial {
		return node.failRequest(ctx, req, "")
	}
	txRequest, err := node.store.ReadRequest(ctx, rid.String())
	logger.Printf("store.ReadRequest(%s) => %v %v", rid.String(), txRequest, err)
	if err != nil || txRequest == nil {
		return node.failRequest(ctx, req, "")
	}

	ms := fmt.Sprintf("REVOKE:%s:%s", rid.String(), tx.TransactionHash)
	err = node.verifySafeMessageSignatureWithHolderOrObserver(ctx, safe, ms, extra[16:])
	logger.Printf("holder: node.verifySafeMessageSignatureWithHolderOrObserver(%v) => %v", req, err)
	if err != nil {
		return node.failRequest(ctx, req, "")
	}

	entry := node.fetchBondAssetReceiver(ctx, safe.Address, tx.AssetId)
	safeAssetId := node.getBondAssetId(ctx, entry, tx.AssetId, tx.Holder)
	bondId := crypto.Sha256Hash([]byte(safeAssetId))
	bond, err := node.fetchAssetMeta(ctx, bondId.String())
	logger.Printf("node.fetchAssetMeta(%v, %s) => %v %v", req, bondId.String(), bond, err)
	if err != nil {
		panic(fmt.Errorf("node.fetchAssetMeta(%s) => %v", bondId.String(), err))
	}
	t := node.buildTransaction(ctx, req.Sequence, node.conf.AppId, bond.AssetId, safe.Receivers, int(safe.Threshold), txRequest.Amount.String(), []byte("refund"), req.Id)
	if t == nil {
		return node.failRequest(ctx, req, bond.AssetId)
	}

	err = node.store.RevokeTransactionWithRequest(ctx, tx, safe, req, []*mtg.Transaction{t})
	if err != nil {
		panic(err)
	}
	return []*mtg.Transaction{t}, ""
}
