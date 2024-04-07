package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	ethereumKeygenRequestTimeKey = "ethereum-keygen-request-time"
)

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
	_, err = node.checkOrDeployKeeperBond(ctx, safe.Chain, ethereumAssetId, "", sp.Holder)
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
	sa, err := ethereum.GetOrDeploySafeAccount(ctx, rpc, node.conf.EVMKey, chainId, owners, 2, timelock, index, t)
	logger.Printf("ethereum.GetOrDeploySafeAccount(%s, %d, %v, %d, %d, %v) => %s %v", rpc, chainId, owners, 2, timelock, t, sa, err)
	return err
}

func (node *Node) ethereumParams(chain byte) (string, string) {
	switch chain {
	case keeper.SafeChainEthereum:
		return node.conf.EthereumRPC, keeper.SafeEthereumChainId
	case keeper.SafeChainMVM:
		return node.conf.MVMRPC, keeper.SafeMVMChainId
	case keeper.SafeChainPolygon:
		return node.conf.PolygonRPC, keeper.SafePolygonChainId
	default:
		panic(chain)
	}
}

func (node *Node) ethereumNetworkInfoLoop(ctx context.Context, chain byte) {
	rpc, assetId := node.ethereumParams(chain)

	for {
		time.Sleep(depositNetworkInfoDelay)
		height, err := ethereum.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
			continue
		}
		delay := node.getChainFinalizationDelay(chain)
		if delay > height || delay < 1 {
			panic(delay)
		}
		height = height + 1 - delay
		info, err := node.keeperStore.ReadLatestNetworkInfo(ctx, chain, time.Now())
		if err != nil {
			panic(err)
		}
		if info != nil && info.Height > uint64(height) {
			logger.Printf("node.keeperStore.ReadLatestNetworkInfo(%d) => %v %d", chain, info, height)
			continue
		}
		gasPrice, err := ethereum.RPCGetGasPrice(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetGasPrice(%d) => %v", chain, err)
			continue
		}
		blockHash, err := ethereum.RPCGetBlockHash(rpc, height)
		if err != nil || blockHash == "" {
			logger.Printf("ethereum.RPCGetBlockHash(%d, %d) => %v", chain, height, err)
			continue
		}
		hash, err := crypto.HashFromString(blockHash[2:])
		if err != nil {
			panic(err)
		}
		extra := []byte{chain}
		extra = binary.BigEndian.AppendUint64(extra, gasPrice.Uint64())
		extra = binary.BigEndian.AppendUint64(extra, uint64(height))
		extra = append(extra, hash[:]...)
		id := common.UniqueId(assetId, fmt.Sprintf("%s:%d", blockHash, height))
		id = common.UniqueId(id, fmt.Sprintf("%d:%d", time.Now().UnixNano(), gasPrice.Uint64()))
		logger.Printf("node.ethereumNetworkInfoLoop(%d) => %d %d %s %s", chain, height, gasPrice.Uint64(), blockHash, id)

		dummy := node.bitcoinDummyHolder()
		action := common.ActionObserverUpdateNetworkStatus
		err = node.sendKeeperResponse(ctx, dummy, byte(action), chain, id, extra)
		logger.Verbosef("node.sendKeeperResponse(%d, %s, %x) => %v", chain, id, extra, err)
	}
}

func (node *Node) ethereumReadBlock(ctx context.Context, num int64, chain byte) error {
	rpc, ethAssetId := node.ethereumParams(chain)

	blockTraces, err := ethereum.RPCDebugTraceBlockByNumber(rpc, num)
	if err != nil {
		return err
	}
	if len(blockTraces) == 0 {
		return nil
	}
	block, err := ethereum.RPCGetBlockWithTransactions(rpc, num)
	if err != nil {
		return err
	}
	erc20Transfers, err := ethereum.GetERC20TransferLogFromBlock(ctx, rpc, int64(chain), num)
	if err != nil {
		return err
	}
	transfers := ethereum.LoopBlockTraces(chain, ethAssetId, blockTraces, block.Tx)
	transfers = append(transfers, erc20Transfers...)

	return node.ethereumProcessBlock(ctx, chain, block, transfers)
}

func (node *Node) ethereumWritePendingDeposit(ctx context.Context, transfer *ethereum.Transfer, chain byte) error {
	old, err := node.keeperStore.ReadDeposit(ctx, transfer.Hash, transfer.Index)
	logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", transfer.Hash, transfer.Index, transfer.AssetId, transfer.Receiver, old, err)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", transfer.Hash, transfer.Index, transfer.AssetId, transfer.Receiver, old, err)
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

	_, err = node.checkOrDeployKeeperBond(ctx, safe.Chain, transfer.AssetId, transfer.TokenAddress, safe.Holder)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", safe.Holder, err)
	}

	var amount decimal.Decimal
	rpc, chainAssetId := node.ethereumParams(chain)
	switch transfer.AssetId {
	case chainAssetId:
		amount = decimal.NewFromBigInt(transfer.Value, -ethereum.ValuePrecision)
	default:
		asset, err := ethereum.FetchAsset(chain, rpc, transfer.TokenAddress)
		if err != nil {
			return err
		}
		amount = decimal.NewFromBigInt(transfer.Value, -int32(asset.Decimals))
	}

	createdAt := time.Now().UTC()
	deposit := &Deposit{
		TransactionHash: transfer.Hash,
		OutputIndex:     transfer.Index,
		AssetId:         transfer.AssetId,
		AssetAddress:    transfer.TokenAddress,
		Amount:          amount.String(),
		Receiver:        transfer.Receiver,
		Sender:          transfer.Sender,
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
	rpc, ethereumAssetId := node.ethereumParams(deposit.Chain)

	asset, err := node.store.ReadAssetMeta(ctx, deposit.AssetId)
	if err != nil || asset == nil {
		return err
	}
	bonded, err := node.checkOrDeployKeeperBond(ctx, deposit.Chain, deposit.AssetId, asset.AssetKey, deposit.Holder)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s) => %v", deposit.Holder, err)
	} else if !bonded {
		return nil
	}
	decimals := int32(ethereum.ValuePrecision)
	switch asset.AssetId {
	case ethereumAssetId:
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
		panic(fmt.Errorf("malicious ethereum network info %v", info))
	}

	match, etx, err := ethereum.VerifyDeposit(ctx, deposit.Chain, rpc, deposit.TransactionHash, ethereumAssetId, deposit.AssetAddress, deposit.Receiver, deposit.OutputIndex, ethereum.ParseAmount(deposit.Amount, decimals))
	if err != nil {
		panic(err)
	}
	if match == nil {
		panic(fmt.Errorf("malicious ethereum deposit %s", deposit.TransactionHash))
	}
	confirmations := info.Height - etx.BlockHeight + 1
	if info.Height < etx.BlockHeight {
		confirmations = 0
	}
	isSafe, err := node.checkSafeInternalAddress(ctx, deposit.Sender)
	if err != nil {
		return fmt.Errorf("node.checkSafeInternalAddress(%s) => %v", deposit.Sender, err)
	}
	if isSafe {
		confirmations = 1000000
	}
	if !ethereum.CheckFinalization(confirmations, deposit.Chain) {
		return nil
	}

	extra := deposit.encodeKeeperExtra(decimals)
	id := common.UniqueId(deposit.AssetId, deposit.Holder)
	id = common.UniqueId(id, fmt.Sprintf("%s:%d", deposit.TransactionHash, deposit.OutputIndex))
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
	duration := 5 * time.Second
	switch chain {
	case ethereum.ChainMVM:
		duration = 1 * time.Second
	case ethereum.ChainPolygon:
		duration = 2 * time.Second
	case ethereum.ChainEthereum:
	}

	for {
		checkpoint, err := node.readDepositCheckpoint(ctx, chain)
		if err != nil {
			panic(err)
		}
		height, err := ethereum.RPCGetBlockHeight(rpc)
		if err != nil {
			logger.Printf("ethereum.RPCGetBlockHeight(%d) => %v", chain, err)
			time.Sleep(time.Second * 5)
			continue
		}
		logger.Printf("node.ethereumReadDepositCheckpoint(%d) => %d %d", chain, checkpoint, height)
		delay := node.getChainFinalizationDelay(chain)
		if checkpoint+delay > height+1 {
			time.Sleep(duration)
			continue
		}
		err = node.ethereumReadBlock(ctx, checkpoint, chain)
		logger.Printf("node.ethereumReadBlock(%d, %d) => %v", chain, checkpoint, err)
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}

		err = node.ethereumWriteDepositCheckpoint(ctx, checkpoint+1, chain)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) ethereumProcessBlock(ctx context.Context, chain byte, block *ethereum.RPCBlockWithTransactions, transfers []*ethereum.Transfer) error {
	rpc, ethAssetId := node.ethereumParams(chain)
	deposits, err := node.parseEthereumBlockDeposits(ctx, chain, transfers)
	if err != nil || len(deposits) == 0 {
		return err
	}

	skips := []string{}
	for k := range deposits {
		items := strings.Split(k, ":")
		if len(items) != 2 {
			panic(k)
		}
		address, tokenAddress := items[0], items[1]

		var assetId string
		var balance *big.Int
		var err error
		switch tokenAddress {
		case ethereum.EthereumEmptyAddress:
			assetId = ethAssetId
			balance, err = ethereum.RPCGetAddressBalanceAtBlock(rpc, block.Number, address)
		default:
			assetId = ethereum.GenerateAssetId(chain, tokenAddress)
			balance, err = ethereum.GetTokenBalanceAtBlock(rpc, tokenAddress, address, big.NewInt(int64(block.Height)))
		}
		if err != nil {
			return err
		}
		safeBalance, err := node.keeperStore.ReadEthereumBalance(ctx, address, assetId)
		if err != nil {
			return err
		}
		balanceAfterDeposit := new(big.Int).Add(safeBalance.Balance, deposits[k])
		if balance.Cmp(balanceAfterDeposit) != 0 {
			logger.Printf("inconsistent %s balance of %s after process block %s: %v %v %v", tokenAddress, address, block.Hash, balance, safeBalance.Balance, deposits[k])
			skips = append(skips, k)
		}
	}

	for _, transfer := range transfers {
		key := fmt.Sprintf("%s:%s", transfer.Receiver, transfer.TokenAddress)
		if slices.Contains(skips, key) {
			continue
		}
		err := node.ethereumWritePendingDeposit(ctx, transfer, chain)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (node *Node) ethereumProcessTransaction(ctx context.Context, tx *ethereum.RPCTransaction, chain byte) error {
	rpc, ethereumAssetId := node.ethereumParams(chain)
	traces, err := ethereum.RPCDebugTraceTransactionByHash(rpc, tx.Hash)
	if err != nil {
		return err
	}
	erc20Transfers, err := ethereum.GetERC20TransferLogFromBlock(ctx, rpc, int64(chain), int64(tx.BlockHeight))
	if err != nil {
		return err
	}
	transfers, _ := ethereum.LoopCalls(chain, ethereumAssetId, tx.Hash, traces, 0)
	transfers = append(transfers, erc20Transfers...)
	for _, transfer := range transfers {
		err := node.ethereumWritePendingDeposit(ctx, transfer, chain)
		if err != nil {
			panic(err)
		}
	}
	return nil
}

func (node *Node) parseEthereumBlockDeposits(ctx context.Context, chain byte, ts []*ethereum.Transfer) (map[string]*big.Int, error) {
	deposits := make(map[string]*big.Int)
	for _, t := range ts {
		if t.Receiver == ethereum.EthereumEmptyAddress {
			continue
		}
		safe, err := node.keeperStore.ReadSafeByAddress(ctx, t.Receiver)
		logger.Verbosef("keeperStore.ReadSafeByAddress(%s) => %v %v", t.Receiver, safe, err)
		if err != nil {
			return nil, fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v %v", t.Receiver, safe, err)
		} else if safe == nil || safe.Chain != chain {
			continue
		}
		old, err := node.keeperStore.ReadDeposit(ctx, t.Hash, t.Index)
		logger.Printf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", t.Hash, t.Index, t.AssetId, t.Receiver, old, err)
		if err != nil {
			return nil, fmt.Errorf("keeperStore.ReadDeposit(%s, %d, %s, %s) => %v %v", t.Hash, t.Index, t.AssetId, t.Receiver, old, err)
		} else if old != nil {
			continue
		}

		key := fmt.Sprintf("%s:%s", t.Receiver, t.TokenAddress)
		total := deposits[key]
		if total != nil {
			deposits[key] = new(big.Int).Add(total, t.Value)
		} else {
			deposits[key] = t.Value
		}
	}
	return deposits, nil
}

func (node *Node) ethereumWriteDepositCheckpoint(ctx context.Context, num int64, chain byte) error {
	return node.store.WriteProperty(ctx, depositCheckpointKey(chain), fmt.Sprint(num))
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
	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", approval.Holder, safe, err)
	if err != nil {
		return err
	}
	if ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Observer) {
		return node.sendToKeeperEthereumApproveRecoveryTransaction(ctx, approval)
	}
	return node.sendToKeeperEthereumApproveNormalTransaction(ctx, approval)
}

func (node *Node) sendToKeeperEthereumApproveNormalTransaction(ctx context.Context, approval *Transaction) error {
	signed, err := node.ethereumCheckKeeperSignedTransaction(ctx, approval)
	logger.Printf("node.ethereumCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
	if err != nil || signed {
		return err
	}
	if !ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
		panic(approval.RawTransaction)
	}

	rawId := common.UniqueId(approval.RawTransaction, approval.RawTransaction)
	raw := common.DecodeHexOrPanic(approval.RawTransaction)
	raw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), raw...)
	raw = common.AESEncrypt(node.aesKey[:], raw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(raw)
	traceId := common.UniqueId(msg, msg)
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

func (node *Node) sendToKeeperEthereumApproveRecoveryTransaction(ctx context.Context, approval *Transaction) error {
	signedRaw := common.DecodeHexOrPanic(approval.RawTransaction)
	st, err := ethereum.UnmarshalSafeTransaction(signedRaw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%s) => %v %v", approval.RawTransaction, st, err)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", approval.Holder, safe, err)
	if err != nil {
		return err
	}
	signedByHolder := ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Holder)

	var extra []byte
	switch {
	case signedByHolder:
		extra = uuid.Nil.Bytes()
	default:
		signed, err := node.ethereumCheckKeeperSignedTransaction(ctx, approval)
		logger.Printf("node.ethereumCheckKeeperSignedTransaction(%v) => %t %v", approval, signed, err)
		if err != nil || signed {
			return err
		}
		tx, err := node.keeperStore.ReadTransaction(ctx, approval.TransactionHash)
		logger.Verbosef("keeperStore.ReadTransaction(%s) => %v %v", approval.TransactionHash, tx, err)
		if err != nil || tx == nil {
			return err
		}
		extra = uuid.Must(uuid.FromString(tx.RequestId)).Bytes()
	}

	objectRaw := signedRaw
	rawId := common.UniqueId(approval.RawTransaction, approval.RawTransaction)
	objectRaw = append(uuid.Must(uuid.FromString(rawId)).Bytes(), objectRaw...)
	objectRaw = common.AESEncrypt(node.aesKey[:], objectRaw, rawId)
	msg := base64.RawURLEncoding.EncodeToString(objectRaw)
	traceId := common.UniqueId(msg, msg)
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
	id := common.UniqueId(safe.Address, st.Destination.Hex())
	extra = append(extra, ref[:]...)
	action := common.ActionEthereumSafeCloseAccount
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

	rpc, ethereumAssetId := node.ethereumParams(safe.Chain)
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
	latestTxTime, err := ethereum.GetSafeLastTxTime(rpc, safe.Address)
	logger.Printf("ethereum.GetSafeLastTxTime(%s %s) => %v %v", rpc, safe.Address, latestTxTime, err)
	if err != nil {
		return err
	}
	if latestTxTime.Add(safe.Timelock + 1*time.Hour).After(latest.Time) {
		return fmt.Errorf("safe %s is locked", safe.Address)
	}

	safeBalances, err := node.keeperStore.ReadEthereumAllBalance(ctx, safe.Address)
	logger.Printf("store.ReadEthereumAllBalance(%s) => %v %v", safe.Address, safeBalances, err)
	if err != nil {
		return err
	} else if len(safeBalances) == 0 {
		return fmt.Errorf("safe %s is has no balances", safe.Address)
	}
	outputs := st.ExtractOutputs()
	if len(outputs) != len(safeBalances) {
		return fmt.Errorf("inconsistent number between outputs and balances: %d, %d", len(outputs), len(safeBalances))
	}
	for _, o := range outputs {
		assetId := ethereumAssetId
		if o.TokenAddress != ethereum.EthereumEmptyAddress {
			assetId = ethereum.GenerateAssetId(safe.Chain, o.TokenAddress)
		}

		b, err := node.keeperStore.ReadEthereumBalance(ctx, safe.Address, assetId)
		logger.Printf("store.ReadEthereumBalance(%s %s) => %v %v", safe.Address, assetId, safeBalances, err)
		if err != nil {
			return err
		}
		if b.Balance.Cmp(o.Amount) != 0 {
			return fmt.Errorf("inconsistent amount between %s balance and output: %d, %d", assetId, b.Balance, o.Amount)
		}
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

	rpc, ethereumAssetId := node.ethereumParams(safe.Chain)
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
	latestTxTime, err := ethereum.GetSafeLastTxTime(rpc, safe.Address)
	logger.Printf("ethereum.GetSafeLastTxTime(%s %s) => %v %v", rpc, safe.Address, latestTxTime, err)
	if err != nil {
		return err
	}
	if latestTxTime.Add(safe.Timelock + 1*time.Hour).After(latest.Time) {
		return fmt.Errorf("safe %s is locked", safe.Address)
	}

	safeBalances, err := node.keeperStore.ReadEthereumAllBalance(ctx, safe.Address)
	logger.Printf("store.ReadEthereumAllBalance(%s) => %v %v", safe.Address, safeBalances, err)
	if err != nil {
		return err
	} else if len(safeBalances) == 0 {
		return fmt.Errorf("safe %s is has no balances", safe.Address)
	}
	outputs := st.ExtractOutputs()
	if len(outputs) != len(safeBalances) {
		return fmt.Errorf("inconsistent number between outputs and balances: %d, %d", len(outputs), len(safeBalances))
	}
	for _, o := range outputs {
		assetId := ethereumAssetId
		if o.TokenAddress != ethereum.EthereumEmptyAddress {
			assetId = ethereum.GenerateAssetId(safe.Chain, o.TokenAddress)
		}

		b, err := node.keeperStore.ReadEthereumBalance(ctx, safe.Address, assetId)
		logger.Printf("store.ReadEthereumBalance(%s %s) => %v %v", safe.Address, assetId, safeBalances, err)
		if err != nil {
			return err
		}
		if b.Balance.Cmp(o.Amount) != 0 {
			return fmt.Errorf("inconsistent amount between %s balance and output: %d, %d", assetId, b.Balance, o.Amount)
		}
	}

	count, err := node.store.CountUnfinishedTransactionApprovalsForHolder(ctx, safe.Holder)
	logger.Printf("store.CountUnfinishedTransactionApprovalsForHolder(%s) => %d %v", safe.Holder, count, err)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

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
	case isHolderSigned: // Close account with holder key
		if !ethereum.CheckTransactionPartiallySignedBy(raw, safe.Holder) {
			return fmt.Errorf("ethereum.CheckTransactionPartiallySignedBy(%s, %s) holder", raw, safe.Holder)
		}
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

func (node *Node) httpRevokeEthereumTransaction(ctx context.Context, txHash string, sigHex string) error {
	logger.Printf("node.httpRevokeEthereumTransaction(%s, %s)", txHash, sigHex)
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

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}
	msg := []byte(fmt.Sprintf("REVOKE:%s:%s", tx.RequestId, tx.TransactionHash))
	err = ethereum.VerifyMessageSignature(tx.Holder, msg, sig)
	logger.Printf("holder: ethereum.VerifyMessageSignature(%v) => %v", tx, err)
	if err != nil {
		safe, err := node.keeperStore.ReadSafe(ctx, tx.Holder)
		if err != nil {
			return err
		}
		err = ethereum.VerifyMessageSignature(safe.Observer, msg, sig)
		logger.Printf("observer: ethereum.VerifyMessageSignature(%v) => %v", tx, err)
		if err != nil {
			return err
		}
	}

	id := common.UniqueId(approval.TransactionHash, approval.TransactionHash)
	rid := uuid.Must(uuid.FromString(tx.RequestId))
	extra := append(rid.Bytes(), sig...)
	action := common.ActionEthereumSafeRevokeTransaction
	err = node.sendKeeperResponse(ctx, tx.Holder, byte(action), approval.Chain, id, extra)
	logger.Printf("node.sendKeeperResponse(%s, %d, %s, %x)", tx.Holder, action, id, extra)
	if err != nil {
		return err
	}

	err = node.store.RevokeTransactionApproval(ctx, txHash, sigHex+":"+approval.RawTransaction)
	logger.Printf("store.RevokeTransactionApproval(%s) => %v", txHash, err)
	return err
}
