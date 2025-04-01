package computer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	solana "github.com/gagliardetto/solana-go"
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
}

// should only return error when mtg could not find outputs from referenced transaction
func (node *Node) GetSystemCallReferenceTxs(ctx context.Context, requestHash string) ([]*store.SpentReference, *crypto.Hash, error) {
	var refs []*store.SpentReference
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

	plan, err := node.store.ReadLatestOperationParams(ctx, req.CreatedAt)
	if err != nil {
		panic(err)
	}
	outputs := node.group.ListOutputsByTransactionHash(ctx, req.MixinHash.String(), req.Sequence)
	total := decimal.NewFromInt(0)
	for _, output := range outputs {
		total = total.Add(output.Amount)
	}
	if total.Compare(plan.OperationPriceAmount) == 1 {
		amount := total.Sub(plan.OperationPriceAmount)
		asset, err := common.SafeReadAssetUntilSufficient(ctx, req.AssetId)
		if err != nil {
			panic(err)
		}
		refs = append(refs, &store.SpentReference{
			TransactionHash: req.MixinHash.String(),
			RequestId:       req.Id,
			RequestHash:     req.MixinHash.String(),
			ChainId:         bot.EthereumChainId,
			AssetId:         bot.XINAssetId,
			Amount:          amount.String(),
			Asset:           asset,
		})
	}

	var storage *crypto.Hash
	for _, ref := range ver.References {
		rs, hash, err := node.getSystemCallReferenceTx(ctx, req, ref.String())
		if err != nil {
			return nil, nil, err
		}
		if len(rs) > 0 {
			refs = append(refs, rs...)
		}
		if hash != nil && storage == nil {
			storage = hash
		}
	}
	return refs, storage, nil
}

func (node *Node) getSystemCallReferenceTx(ctx context.Context, req *store.Request, hash string) ([]*store.SpentReference, *crypto.Hash, error) {
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
			extra, err := base64.RawURLEncoding.DecodeString(value)
			if err != nil {
				panic(err)
			}
			ver.Extra = extra
		}
	}
	// skip referenced storage transaction
	if ver.Asset.String() == common.XinKernelAssetId && len(ver.Extra) > mc.ExtraSizeGeneralLimit {
		h, _ := crypto.HashFromString(hash)
		return nil, &h, nil
	}
	outputs := node.group.ListOutputsByTransactionHash(ctx, hash, req.Sequence)
	if len(outputs) == 0 {
		return nil, nil, fmt.Errorf("unreceived reference %s", hash)
	}
	total := decimal.NewFromInt(0)
	for _, output := range outputs {
		total = total.Add(output.Amount)
	}
	asset, err := common.SafeReadAssetUntilSufficient(ctx, outputs[0].AssetId)
	if err != nil {
		panic(err)
	}
	refs := []*store.SpentReference{
		{
			TransactionHash: hash,
			RequestId:       req.Id,
			RequestHash:     req.MixinHash.String(),
			ChainId:         asset.ChainID,
			AssetId:         asset.AssetID,
			Amount:          total.String(),
			Asset:           asset,
		},
	}
	return refs, nil, nil
}

func (node *Node) GetSystemCallRelatedAsset(ctx context.Context, rs []*store.SpentReference) map[string]*ReferencedTxAsset {
	am := make(map[string]*ReferencedTxAsset)
	for _, ref := range rs {
		logger.Printf("node.GetReferencedTxAsset() => %v", ref)
		amt, err := decimal.NewFromString(ref.Amount)
		if err != nil {
			panic(err)
		}

		isSolAsset := ref.ChainId == solanaApp.SolanaChainBase
		address := ref.Asset.AssetKey
		if !isSolAsset {
			da, err := node.store.ReadDeployedAsset(ctx, ref.AssetId, common.RequestStateDone)
			if err != nil || da == nil {
				panic(fmt.Errorf("store.ReadDeployedAsset(%s) => %v %v", ref.AssetId, da, err))
			}
			address = da.Address
		}
		ra := &ReferencedTxAsset{
			Solana:  isSolAsset,
			Address: address,
			Decimal: ref.Asset.Precision,
			Amount:  amt,
			AssetId: ref.AssetId,
			ChainId: ref.Asset.ChainID,
		}
		old := am[ref.AssetId]
		if old != nil {
			ra.Amount = ra.Amount.Add(old.Amount)
		}
		am[ref.AssetId] = ra
	}
	for _, a := range am {
		logger.Printf("node.GetSystemCallRelatedAsset() => %v", a)
		if !a.Amount.IsPositive() {
			panic(a)
		}
	}
	return am
}

func (node *Node) getPostprocessCall(ctx context.Context, req *store.Request, call *store.SystemCall) (*store.SystemCall, error) {
	if call.Type != store.CallTypeMain {
		return nil, nil
	}
	if !common.CheckTestEnvironment(ctx) {
		ver, err := common.VerifyKernelTransaction(ctx, node.group, req.Output, KernelTimeout)
		if err != nil {
			panic(err)
		}
		if len(ver.References) != 1 {
			return nil, nil
		}
	}

	postprocess, tx, err := node.getSubSystemCallFromReferencedStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	postprocess.Superior = call.RequestId
	postprocess.Type = store.CallTypePostProcess
	postprocess.Public = call.Public
	postprocess.State = common.RequestStatePending

	user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
	if err != nil {
		panic(err)
	}
	if user == nil {
		return nil, fmt.Errorf("store.ReadUser(%s) => nil", call.UserIdFromPublicPath().String())
	}
	err = node.VerifySubSystemCall(ctx, tx, solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry), solana.MustPublicKeyFromBase58(user.ChainAddress))
	logger.Printf("node.VerifySubSystemCall(%s) => %v", user.ChainAddress, err)
	if err != nil {
		return nil, err
	}
	return postprocess, nil
}

func (node *Node) getSubSystemCallFromReferencedStorage(ctx context.Context, req *store.Request) (*store.SystemCall, *solana.Transaction, error) {
	var references []crypto.Hash
	if common.CheckTestEnvironment(ctx) {
		references = outputReferences[req.Output.OutputId]
	} else {
		ver, err := common.VerifyKernelTransaction(ctx, node.group, req.Output, KernelTimeout)
		if err != nil {
			panic(err)
		}
		if len(ver.References) != 1 {
			return nil, nil, fmt.Errorf("invalid count of references from request: %v %v", req, ver)
		}
		references = ver.References
	}
	data := node.readStorageExtraFromObserver(ctx, references[0])
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
	err = node.solanaClient().ProcessTransactionWithAddressLookups(ctx, tx)
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
		RequestId:    id,
		RequestHash:  req.MixinHash.String(),
		NonceAccount: advance.GetNonceAccount().PublicKey.String(),
		Message:      hex.EncodeToString(msg),
		Raw:          tx.MustToBase64(),
		State:        common.RequestStateInitial,
		CreatedAt:    req.CreatedAt,
		UpdatedAt:    req.CreatedAt,
	}
	if withdrawn {
		call.WithdrawalTraces = sql.NullString{Valid: true, String: ""}
		call.WithdrawnAt = sql.NullTime{Valid: true, Time: req.CreatedAt}
	}
	return call, tx, nil
}

func (node *Node) checkUserSystemCall(ctx context.Context, tx *solana.Transaction, user solana.PublicKey) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}

	if !tx.IsSigner(node.solanaPayer()) {
		return fmt.Errorf("tx.IsSigner(payer) => %t", false)
	}

	index := -1
	for i, acc := range tx.Message.AccountKeys {
		if !acc.Equals(node.solanaPayer()) {
			continue
		}
		index = i
	}
	for i, ins := range tx.Message.Instructions {
		if slices.Contains(ins.Accounts, uint16(index)) {
			return fmt.Errorf("invalid instruction: %d %v", i, ins)
		}
	}
	return nil
}
