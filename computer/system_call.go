package computer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/gagliardetto/solana-go"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type ReferencedTxAsset struct {
	Solana  bool
	Amount  decimal.Decimal
	Decimal int
	Address string
	AssetId string
	ChainId string
	Fee     bool
}

// should only return error when mtg could not find outputs from referenced transaction
// all assets needed in system call should be referenced
// extra amount of XIN is used for fees in system call like rent
func (node *Node) GetSystemCallReferenceOutputs(ctx context.Context, uid, requestHash string, state byte) ([]*store.UserOutput, *crypto.Hash, error) {
	var outputs []*store.UserOutput
	req, err := node.store.ReadRequestByHash(ctx, requestHash)
	if err != nil || req == nil {
		panic(fmt.Errorf("store.ReadRequestByHash(%s) => %v %v", requestHash, req, err))
	}
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, req.MixinHash.String())
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", req.MixinHash.String(), ver, err))
	}
	if common.CheckTestEnvironment(ctx) {
		ver.References = readOutputReferences(req.Id)
	}

	var storage *crypto.Hash
	for _, ref := range ver.References {
		os, hash, err := node.getSystemCallReferenceTx(ctx, uid, ref.String(), state)
		if err != nil {
			return nil, nil, err
		}
		if len(os) > 0 {
			outputs = append(outputs, os...)
		}
		if hash == nil {
			continue
		}
		if storage == nil {
			storage = hash
		} else if storage.String() != hash.String() {
			panic(storage.String())
		}
	}
	return outputs, storage, nil
}

func (node *Node) getSystemCallReferenceTx(ctx context.Context, uid, hash string, state byte) ([]*store.UserOutput, *crypto.Hash, error) {
	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, hash)
	if err != nil || ver == nil {
		panic(fmt.Errorf("group.ReadKernelTransactionUntilSufficient(%s) => %v %v", hash, ver, err))
	}
	if common.CheckTestEnvironment(ctx) {
		value, err := node.store.ReadProperty(ctx, hash)
		if err != nil {
			panic(err)
		}
		if len(value) > 0 {
			switch hash {
			case "a8eed784060b200ea7f417309b12a33ced8344c24f5cdbe0237b7fc06125f459", "01c43005fd06e0b8f06a0af04faf7530331603e352a11032afd0fd9dbd84e8ee":
				raw := common.DecodeHexOrPanic(value)
				ver, err = mc.UnmarshalVersionedTransaction(raw)
				if err != nil {
					panic(err)
				}
			default:
				extra, err := base64.RawURLEncoding.DecodeString(value)
				if err != nil {
					panic(err)
				}
				ver.Extra = extra
			}
		}
	}
	// skip referenced storage transaction
	if ver.Asset.String() == common.XINKernelAssetId && len(ver.Extra) > mc.ExtraSizeGeneralLimit {
		h, _ := crypto.HashFromString(hash)
		return nil, &h, nil
	}

	asset, err := common.SafeReadAssetUntilSufficient(ctx, ver.Asset.String())
	if err != nil {
		panic(err)
	}
	outputs, err := node.store.ListUserOutputsByHashAndState(ctx, uid, hash, state)
	if err != nil {
		panic(err)
	}
	if len(outputs) == 0 {
		return nil, nil, fmt.Errorf("unreceived reference %s", hash)
	}
	for _, o := range outputs {
		o.Asset = *asset
	}
	return outputs, nil, nil
}

// be used to refund by mtg without fee
// be used to create prepare call by observer with fee from payer (isolatedFee = true)
// be used to create post call by observer with fee to calculate rest SOL
func (node *Node) GetSystemCallRelatedAsset(ctx context.Context, os []*store.UserOutput) []*ReferencedTxAsset {
	am := make(map[string]*ReferencedTxAsset)
	for _, output := range os {
		logger.Printf("node.GetReferencedTxAsset() => %v", output)
		amt := decimal.RequireFromString(output.Amount)
		isSolAsset := output.ChainId == solanaApp.SolanaChainBase
		address := output.Asset.AssetKey
		if !isSolAsset {
			da, err := node.store.ReadDeployedAsset(ctx, output.AssetId)
			if err != nil || da == nil {
				panic(fmt.Errorf("store.ReadDeployedAsset(%s) => %v %v", output.AssetId, da, err))
			}
			address = da.Address
		}
		ra := &ReferencedTxAsset{
			Solana:  isSolAsset,
			Address: address,
			Decimal: output.Asset.Precision,
			Amount:  amt,
			AssetId: output.AssetId,
			ChainId: output.Asset.ChainID,
			Fee:     false,
		}
		if old := am[output.AssetId]; old != nil {
			ra.Amount = ra.Amount.Add(old.Amount)
		}
		am[output.AssetId] = ra
	}
	var assets []*ReferencedTxAsset
	for _, a := range am {
		logger.Printf("node.GetSystemCallRelatedAsset() => %v", a)
		if !a.Amount.IsPositive() {
			panic(a.AssetId)
		}
		assets = append(assets, a)
	}
	return assets
}

// should only return error when no valid fees found
func (node *Node) getSystemCallFeeFromXIN(ctx context.Context, call *store.SystemCall) (*store.UserOutput, error) {
	req, err := node.store.ReadRequestByHash(ctx, call.RequestHash)
	if err != nil {
		panic(err)
	}
	extra := req.ExtraBytes()
	if len(extra) != 41 {
		return nil, nil
	}
	feeId := uuid.Must(uuid.FromBytes(extra[25:])).String()

	var fee *store.FeeInfo
	fee, err = node.store.ReadFeeInfoById(ctx, feeId)
	logger.Printf("store.ReadFeeInfoById(%s) => %v %v", feeId, fee, err)
	if err != nil {
		panic(err)
	}
	if fee == nil { // TODO check fee timestamp against the call timestamp not too old
		return nil, fmt.Errorf("invalid fee id: %s", feeId)
	}

	ratio := decimal.RequireFromString(fee.Ratio)
	plan, err := node.store.ReadLatestOperationParams(ctx, req.CreatedAt)
	if err != nil {
		panic(err)
	}

	if req.Amount.Compare(plan.OperationPriceAmount) <= 0 {
		return nil, nil
	}
	feeOnXIN := req.Amount.Sub(plan.OperationPriceAmount)
	feeOnSol := feeOnXIN.Mul(ratio).RoundCeil(8).String()

	asset, err := common.SafeReadAssetUntilSufficient(ctx, common.SafeSolanaChainId)
	if err != nil {
		panic(err)
	}

	return &store.UserOutput{
		OutputId:        req.Id,
		UserId:          call.UserIdFromPublicPath(),
		TransactionHash: req.MixinHash.String(),
		OutputIndex:     req.MixinIndex,
		AssetId:         common.SafeSolanaChainId,
		ChainId:         common.SafeSolanaChainId,
		Amount:          feeOnSol,
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,

		Asset: *asset,
	}, nil
}

func (node *Node) getPostProcessCall(ctx context.Context, req *store.Request, call *store.SystemCall, data []byte) (*store.SystemCall, error) {
	if call.Type != store.CallTypeMain || len(data) == 0 {
		return nil, nil
	}

	post, tx, err := node.getSubSystemCallFromExtra(ctx, req, data)
	if err != nil {
		return nil, err
	}
	post.Superior = call.RequestId
	post.Type = store.CallTypePostProcess
	post.Public = call.Public
	post.State = common.RequestStatePending

	user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
	if err != nil {
		panic(err)
	}
	if user == nil {
		return nil, fmt.Errorf("store.ReadUser(%s) => nil", call.UserIdFromPublicPath())
	}
	mtgDeposit := solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry)
	err = node.VerifySubSystemCall(ctx, tx, mtgDeposit, solana.MustPublicKeyFromBase58(user.ChainAddress))
	logger.Printf("node.VerifySubSystemCall(%s) => %v", user.ChainAddress, err)
	if err != nil {
		return nil, err
	}

	os, _, err := node.GetSystemCallReferenceOutputs(ctx, call.UserIdFromPublicPath(), call.RequestHash, common.RequestStatePending)
	if err != nil {
		panic(fmt.Errorf("node.GetSystemCallReferenceTxs(%s) => %v", call.RequestId, err))
	}
	ras := node.GetSystemCallRelatedAsset(ctx, os)
	err = node.comparePostCallWithSolanaTx(ctx, ras, tx, call.Hash.String, user.ChainAddress)
	logger.Printf("node.comparePostCallWithSolanaTx(%s %s) => %v", call.Hash.String, user.ChainAddress, err)
	if err != nil {
		return nil, err
	}
	return post, nil
}

func (node *Node) getSubSystemCallFromExtra(ctx context.Context, req *store.Request, data []byte) (*store.SystemCall, *solana.Transaction, error) {
	if len(data) < 16 {
		return nil, nil, fmt.Errorf("invalid data length: %d", len(data))
	}
	id, raw := uuid.Must(uuid.FromBytes(data[:16])).String(), data[16:]
	return node.buildSystemCallFromBytes(ctx, req, id, raw, true)
}

// should only return error when fail to parse nonce advance instruction;
// without fields of superior, type, public, skip_postprocess
func (node *Node) buildSystemCallFromBytes(ctx context.Context, req *store.Request, id string, raw []byte, withdrawn bool) (*store.SystemCall, *solana.Transaction, error) {
	tx, err := solana.TransactionFromBytes(raw)
	logger.Printf("solana.TransactionFromBytes(%x) => %v %v", raw, tx, err)
	if err != nil {
		return nil, nil, err
	}
	err = node.processTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		panic(err)
	}
	advance, err := solanaApp.NonceAccountFromTx(tx)
	logger.Printf("solana.NonceAccountFromTx() => %v %v", advance, err)
	if err != nil {
		return nil, nil, err
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	call := &store.SystemCall{
		RequestId:       id,
		RequestHash:     req.MixinHash.String(),
		NonceAccount:    advance.GetNonceAccount().PublicKey.String(),
		MessageHash:     crypto.Sha256Hash(msg).String(),
		Raw:             tx.MustToBase64(),
		State:           common.RequestStateInitial,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.CreatedAt,
		RequestSignerAt: sql.NullTime{Valid: true, Time: req.CreatedAt},
	}
	if withdrawn {
		call.WithdrawalTraces = sql.NullString{Valid: true, String: ""}
	}
	return call, tx, nil
}

func (node *Node) checkUserSystemCall(ctx context.Context, tx *solana.Transaction) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}

	// ensure the transaction is signed by fee payer
	if !tx.IsSigner(node.SolanaPayer()) {
		return fmt.Errorf("tx.IsSigner(payer) => %t", false)
	}

	// make sure fee payer is only used for the first nonce advance transaction
	index, err := solanaApp.GetSignatureIndexOfAccount(*tx, node.SolanaPayer())
	if err != nil {
		return err
	}
	for i, ins := range tx.Message.Instructions[1:] {
		if slices.Contains(ins.Accounts, uint16(index)) {
			return fmt.Errorf("invalid instruction: %d %v", i+1, ins)
		}
	}
	return nil
}

func (node *Node) comparePrepareCallWithSolanaTx(tx *solana.Transaction, as []*ReferencedTxAsset) error {
	changes := make(map[string]*solanaApp.Transfer)
	for _, ix := range tx.Message.Instructions {
		transfer := solanaApp.ExtractInitialTransfersFromInstruction(&tx.Message, ix)
		if transfer == nil || transfer.Sender == node.SolanaPayer().String() {
			continue
		}
		key := transfer.TokenAddress
		old := changes[key]
		if old != nil {
			changes[key].Value = new(big.Int).Add(old.Value, transfer.Value)
			continue
		}
		changes[key] = transfer
	}

	for _, a := range as {
		expected := a.Amount.Mul(decimal.New(1, int32(a.Decimal))).BigInt()
		old := changes[a.Address]
		if old == nil {
			return fmt.Errorf("invalid missed referenced asset: %v", a)
		}
		if old.Value.Cmp(expected) != 0 {
			return fmt.Errorf("invalid referenced asset: %s %s %s", a.AssetId, old.Value.String(), expected.String())
		}
	}
	return nil
}

func (node *Node) comparePostCallWithSolanaTx(ctx context.Context, as []*ReferencedTxAsset, tx *solana.Transaction, signature, user string) error {
	rpcTx, err := node.solana.RPCGetTransaction(ctx, signature)
	if err != nil || rpcTx == nil {
		panic(fmt.Errorf("solana.RPCGetTransaction(%s) => %v %v", signature, rpcTx, err))
	}
	utx, err := rpcTx.Transaction.GetTransaction()
	if err != nil {
		panic(err)
	}
	err = node.processTransactionWithAddressLookups(ctx, utx)
	if err != nil {
		panic(err)
	}

	assets := make(map[string]*ReferencedTxAsset)
	for _, a := range as {
		if assets[a.Address] != nil {
			assets[a.Address].Amount = assets[a.Address].Amount.Add(a.Amount)
			continue
		}
		assets[a.Address] = a
	}
	cs := node.buildUserBalanceChangesFromMeta(ctx, utx, rpcTx.Meta, solana.MPK(user))
	for address, change := range cs {
		old := assets[address]
		if old != nil {
			assets[address].Amount = assets[address].Amount.Add(change.Amount)
			continue
		}
		if !change.Amount.IsNegative() {
			continue
		}
		assets[address] = &ReferencedTxAsset{
			Address: address,
			Decimal: int(change.Decimals),
			Amount:  change.Amount,
		}
	}

	changes := make(map[string]*solanaApp.Transfer)
	for _, ix := range tx.Message.Instructions {
		transfer := solanaApp.ExtractInitialTransfersFromInstruction(&tx.Message, ix)
		if transfer == nil || transfer.Sender == node.SolanaPayer().String() {
			continue
		}
		key := transfer.TokenAddress
		old := changes[key]
		if old != nil {
			changes[key].Value = new(big.Int).Add(old.Value, transfer.Value)
			continue
		}
		changes[key] = transfer
	}
	for address, c := range changes {
		old := assets[address]
		if old == nil {
			return fmt.Errorf("invalid missed user balance change: %s", address)
		}
		ea := old.Amount.Mul(decimal.New(1, int32(old.Decimal))).BigInt()
		if ea.Cmp(c.Value) != 0 {
			return fmt.Errorf("invalid user balance change: %s %s %s", address, c.Value.String(), ea.String())
		}
	}
	return nil
}

func (node *Node) compareDepositCallWithSolanaTx(ctx context.Context, tx *solana.Transaction, signature, user string) error {
	rpcTx, err := node.solana.RPCGetTransaction(ctx, signature)
	if err != nil || rpcTx == nil {
		panic(fmt.Errorf("solana.RPCGetTransaction(%s) => %v %v", signature, rpcTx, err))
	}
	dtx, err := rpcTx.Transaction.GetTransaction()
	if err != nil {
		panic(err)
	}
	err = node.checkCreatedAtaUntilSufficient(ctx, dtx)
	if err != nil {
		panic(err)
	}
	err = node.processTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		panic(err)
	}
	transfers, err := solanaApp.ExtractTransfersFromTransaction(ctx, dtx, rpcTx.Meta, nil)
	if err != nil {
		panic(err)
	}
	expectedChanges, err := node.parseSolanaBlockBalanceChanges(ctx, transfers)
	if err != nil {
		panic(err)
	}

	transfers = nil
	for _, ix := range tx.Message.Instructions {
		if transfer := solanaApp.ExtractInitialTransfersFromInstruction(&tx.Message, ix); transfer != nil {
			transfers = append(transfers, transfer)
		}
	}
	actualChanges := make(map[string]*big.Int)
	for _, t := range transfers {
		if t.Sender != user || t.Receiver != node.getMTGAddress(ctx).String() {
			continue
		}
		key := fmt.Sprintf("%s:%s", t.Receiver, t.TokenAddress)
		total := actualChanges[key]
		if total != nil {
			actualChanges[key] = new(big.Int).Add(total, t.Value)
		} else {
			actualChanges[key] = t.Value
		}
	}
	for key, actual := range actualChanges {
		expected := expectedChanges[key]
		if expected == nil {
			return fmt.Errorf("non-existed deposit: %s %s %s", signature, key, tx.MustToBase64())
		}
		if expected.Cmp(actual) != 0 {
			return fmt.Errorf("invalid deposit: %s %s %s %s %s", signature, key, expected.String(), actual.String(), tx.MustToBase64())
		}
	}
	return nil
}

func attachSystemCall(extra []byte, cid string, raw []byte) []byte {
	extra = append(extra, uuid.Must(uuid.FromString(cid)).Bytes()...)
	extra = append(extra, raw...)
	return extra
}
