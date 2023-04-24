package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
)

type Deposit struct {
	Chain  byte
	Asset  string
	Hash   string
	Index  uint64
	Amount *big.Int
}

func parseDepositExtra(req *common.Request) (*Deposit, error) {
	extra, err := hex.DecodeString(req.Extra)
	if err != nil || len(extra) < 1+16+32+8 {
		return nil, fmt.Errorf("invalid deposit extra %s", req.Extra)
	}
	deposit := &Deposit{
		Chain: extra[0],
		Asset: uuid.Must(uuid.FromBytes(extra[1:17])).String(),
	}
	extra = extra[17:]
	switch deposit.Chain {
	case SafeChainBitcoin:
		deposit.Hash = hex.EncodeToString(extra[0:32])
		deposit.Index = binary.BigEndian.Uint64(extra[32:40])
		deposit.Amount = new(big.Int).SetBytes(extra[40:])
		if !deposit.Amount.IsInt64() {
			return nil, fmt.Errorf("invalid deposit amount %s", deposit.Amount.String())
		}
	case SafeChainEthereum:
		deposit.Hash = "0x" + hex.EncodeToString(extra[0:32])
		deposit.Index = binary.BigEndian.Uint64(extra[32:40])
		deposit.Amount = new(big.Int).SetBytes(extra[40:])
	default:
		return nil, fmt.Errorf("invalid deposit chain %d", deposit.Chain)
	}

	return deposit, nil
}

func (node *Node) CreateHolderDeposit(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	deposit, err := parseDepositExtra(req)
	logger.Printf("req.parseDepositExtra(%v) => %v %v", req, deposit, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != deposit.Chain {
		return node.store.FinishRequest(ctx, req.Id)
	}

	bondId, bondChain, err := node.getBondAsset(ctx, deposit.Asset, req.Holder)
	if err != nil {
		return fmt.Errorf("node.getBondAsset(%s, %s) => %v", deposit.Asset, req.Holder, err)
	}
	bond, err := node.fetchAssetMeta(ctx, bondId.String())
	logger.Printf("node.fetchAssetMeta(%v, %s) => %v %v", req, bondId.String(), bond, err)
	if err != nil {
		return fmt.Errorf("node.fetchAssetMeta(%s) => %v", bondId.String(), err)
	}
	if bond.Chain != bondChain {
		panic(bond.AssetId)
	}
	if bond == nil || bond.Decimals != 18 {
		return node.store.FinishRequest(ctx, req.Id)
	}
	asset, err := node.fetchAssetMeta(ctx, deposit.Asset)
	if err != nil {
		return fmt.Errorf("node.fetchAssetMeta(%s) => %v", deposit.Asset, err)
	}
	if asset.Chain != safe.Chain {
		panic(asset.AssetId)
	}

	plan, err := node.store.ReadAccountPlan(ctx, deposit.Chain)
	logger.Printf("store.ReadAccountPlan(%d) => %v %v", deposit.Chain, plan, err)
	if err != nil {
		return fmt.Errorf("store.ReadAccountPlan(%d) => %v", deposit.Chain, err)
	} else if plan == nil || !plan.TransactionMinimum.IsPositive() {
		return node.store.FinishRequest(ctx, req.Id)
	}

	switch deposit.Chain {
	case SafeChainBitcoin:
		return node.doBitcoinHolderDeposit(ctx, req, deposit, safe, bond.AssetId, asset, plan.TransactionMinimum)
	case SafeChainEthereum:
		panic(0)
	default:
		return node.store.FinishRequest(ctx, req.Id)
	}
}

// FIXME Keeper should deny new deposits when too many unspent outputs
func (node *Node) doBitcoinHolderDeposit(ctx context.Context, req *common.Request, deposit *Deposit, safe *store.Safe, bondId string, asset *store.Asset, minimum decimal.Decimal) error {
	if asset.Decimals != bitcoin.ValuePrecision {
		panic(asset.Decimals)
	}
	old, err := node.store.ReadBitcoinUTXO(ctx, deposit.Hash, int(deposit.Index))
	logger.Printf("store.ReadBitcoinUTXO(%s, %d) => %v %v", deposit.Hash, deposit.Index, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadBitcoinUTXO(%s, %d) => %v", deposit.Hash, deposit.Index, err)
	} else if old != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	amount := decimal.NewFromBigInt(deposit.Amount, -int32(asset.Decimals))
	change, err := node.store.ReadTransaction(ctx, deposit.Hash)
	logger.Printf("store.ReadTransaction(%s) => %v %v", deposit.Hash, change, err)
	if err != nil {
		return fmt.Errorf("store.ReadTransaction(%s) => %v", deposit.Hash, err)
	}
	if amount.Cmp(minimum) < 0 && change == nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	if amount.Cmp(decimal.New(bitcoin.ValueDust, -bitcoin.ValuePrecision)) < 0 {
		panic(deposit.Hash)
	}

	output, err := node.verifyBitcoinTransaction(ctx, req, deposit, safe, bitcoin.InputTypeP2WSHMultisigHolderSigner)
	logger.Printf("node.verifyBitcoinTransaction(%v) => %v %v", req, output, err)
	if err != nil {
		return fmt.Errorf("node.verifyBitcoinTransaction(%s) => %v", deposit.Hash, err)
	}
	if output == nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	if change == nil || deposit.Index == 0 {
		err = node.buildTransaction(ctx, bondId, safe.Receivers, int(safe.Threshold), amount.String(), nil, req.Id)
		if err != nil {
			return fmt.Errorf("node.buildTransaction(%v) => %v", req, err)
		}
	}

	return node.store.WriteBitcoinOutputFromRequest(ctx, safe.Address, output, req, false)
}

func (node *Node) CreateAccountantDeposit(ctx context.Context, req *common.Request) error {
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	deposit, err := parseDepositExtra(req)
	logger.Printf("req.parseDepositExtra(%v) => %v %v", req, deposit, err)
	if err != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}
	safe, err := node.store.ReadSafe(ctx, req.Holder)
	if err != nil {
		return fmt.Errorf("store.ReadSafe(%s) => %v", req.Holder, err)
	}
	if safe == nil || safe.Chain != deposit.Chain {
		return node.store.FinishRequest(ctx, req.Id)
	}
	asset, err := node.fetchAssetMeta(ctx, deposit.Asset)
	if err != nil {
		return fmt.Errorf("node.fetchAssetMeta(%s) => %v", deposit.Asset, err)
	}
	if asset.Chain != safe.Chain {
		panic(asset.AssetId)
	}
	switch deposit.Chain {
	case SafeChainBitcoin:
		return node.doBitcoinAccountantDeposit(ctx, req, deposit, safe, asset)
	case SafeChainEthereum:
		panic(0)
	default:
		return node.store.FinishRequest(ctx, req.Id)
	}
}

func (node *Node) doBitcoinAccountantDeposit(ctx context.Context, req *common.Request, deposit *Deposit, safe *store.Safe, asset *store.Asset) error {
	if asset.Decimals != bitcoin.ValuePrecision {
		panic(asset.Decimals)
	}
	old, err := node.store.ReadBitcoinUTXO(ctx, deposit.Hash, int(deposit.Index))
	logger.Printf("store.ReadBitcoinUTXO(%s, %d) => %v %v", deposit.Hash, deposit.Index, old, err)
	if err != nil {
		return fmt.Errorf("store.ReadBitcoinUTXO(%s, %d) => %v", deposit.Hash, deposit.Index, err)
	} else if old != nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant)
	if err != nil {
		panic(err)
	}

	output, err := node.verifyBitcoinTransaction(ctx, req, deposit, safe, bitcoin.InputTypeP2WPKHAccoutant)
	logger.Printf("node.verifyBitcoinTransaction(%v) => %v %v", req, output, err)
	if err != nil {
		return fmt.Errorf("node.verifyBitcoinTransaction(%s) => %v", deposit.Hash, err)
	}
	if output == nil {
		return node.store.FinishRequest(ctx, req.Id)
	}

	return node.store.WriteBitcoinOutputFromRequest(ctx, wka.Address, output, req, true)
}

func (node *Node) verifyBitcoinTransaction(ctx context.Context, req *common.Request, deposit *Deposit, safe *store.Safe, typ int) (*bitcoin.Input, error) {
	if safe.Chain != SafeChainBitcoin {
		panic(safe.Chain)
	}
	if deposit.Asset != SafeBitcoinChainId {
		return nil, nil
	}

	input := &bitcoin.Input{
		TransactionHash: deposit.Hash,
		Index:           uint32(deposit.Index),
		Satoshi:         deposit.Amount.Int64(),
	}

	var receiver string
	switch typ {
	case bitcoin.InputTypeP2WPKHAccoutant:
		wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant)
		if err != nil {
			panic(err)
		}
		receiver = wka.Address
		input.Script = wka.Script
		input.Sequence = bitcoin.MaxTransactionSequence
	case bitcoin.InputTypeP2WSHMultisigHolderSigner:
		wsa, err := bitcoin.BuildWitnessScriptAccount(safe.Holder, safe.Signer, safe.Observer, safe.Timelock)
		if err != nil {
			panic(err)
		}
		if wsa.Address != safe.Address {
			panic(safe.Address)
		}
		receiver = wsa.Address
		input.Script = wsa.Script
		input.Sequence = wsa.Sequence
	default:
		panic(typ)
	}

	info, err := node.store.ReadLatestNetworkInfo(ctx, safe.Chain)
	logger.Printf("store.ReadLatestNetworkInfo(%d) => %v %v", safe.Chain, info, err)
	if err != nil || info == nil {
		return nil, err
	}
	if info.CreatedAt.Add(SafeNetworkInfoTimeout).Before(req.CreatedAt) {
		return nil, nil
	}
	if info.CreatedAt.After(req.CreatedAt) {
		return nil, fmt.Errorf("malicious bitcoin network info %v", info)
	}

	tx, output, err := bitcoin.RPCGetTransactionOutput(node.conf.BitcoinRPC, deposit.Hash, int64(deposit.Index))
	logger.Printf("bitcoin.RPCGetTransactionOutput(%s, %d) => %v %v", deposit.Hash, deposit.Index, output, err)
	if err != nil || output == nil {
		return nil, fmt.Errorf("malicious bitcoin deposit or node not in sync? %s %v", deposit.Hash, err)
	}
	if output.Address != receiver || output.Satoshi != input.Satoshi {
		return nil, fmt.Errorf("malicious bitcoin deposit %s", deposit.Hash)
	}

	confirmations := info.Height - output.Height + 1
	if info.Height < output.Height {
		confirmations = 0
	}
	sender, err := bitcoin.RPCGetTransactionSender(node.conf.BitcoinRPC, tx)
	if err != nil {
		return nil, fmt.Errorf("bitcoin.RPCGetTransactionSender(%s) => %v", tx.TxId, err)
	}
	isDomain, err := common.CheckMixinDomainAddress(node.conf.MixinRPC, SafeBitcoinChainId, sender)
	if err != nil {
		return nil, fmt.Errorf("common.CheckMixinDomainAddress(%s) => %v", sender, err)
	}
	if isDomain {
		confirmations = 1000000
	}
	isSafe, err := node.checkSafeInternalAddress(ctx, sender)
	if err != nil {
		return nil, fmt.Errorf("node.checkSafeInternalAddress(%s) => %v", sender, err)
	}
	if isSafe {
		confirmations = 1000000
	}
	if !bitcoin.CheckFinalization(confirmations, output.Coinbase) {
		return nil, fmt.Errorf("bitcoin.CheckFinalization(%s)", tx.TxId)
	}

	return input, nil
}

func (node *Node) checkSafeInternalAddress(ctx context.Context, receiver string) (bool, error) {
	safe, err := node.store.ReadSafeByAddress(ctx, receiver)
	if err != nil {
		return false, fmt.Errorf("store.ReadSafeByAddress(%s) => %v", receiver, err)
	}
	holder, err := node.store.ReadAccountantHolder(ctx, receiver)
	if err != nil {
		return false, fmt.Errorf("store.ReadAccountantHolder(%s) => %v", receiver, err)
	}
	return safe != nil || holder != "", nil
}
