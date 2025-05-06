package computer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/ethereum"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	solana "github.com/gagliardetto/solana-go"
	lookup "github.com/gagliardetto/solana-go/programs/address-lookup-table"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	SolanaBlockDelay = 32
	SolanaBlockBatch = 30
	SolanaTxRetry    = 10
)

func (node *Node) solanaRPCBlocksLoop(ctx context.Context) {
	client := node.SolanaClient()

	for {
		checkpoint, err := node.readSolanaBlockCheckpoint(ctx)
		if err != nil {
			panic(err)
		}
		height, err := client.RPCGetBlockHeight(ctx)
		if err != nil {
			logger.Printf("solana.RPCGetBlockHeight => %v", err)
			time.Sleep(time.Second * 5)
			continue
		}
		offset := checkpoint

		var wg sync.WaitGroup
		wg.Add(SolanaBlockBatch)
		for i := range SolanaBlockBatch {
			go func(i int) {
				defer wg.Done()
				current := checkpoint + int64(i)
				if current+SolanaBlockDelay > int64(height)+1 {
					logger.Printf("current %d > limit %d", current+SolanaBlockDelay, int64(height)+1)
					return
				}
				err := node.solanaReadBlock(ctx, current)
				logger.Printf("node.solanaReadBlock(%d) => %v", current, err)
				if err != nil {
					panic(err)
				}
				if current > offset {
					offset = current
				}
			}(i)
		}
		wg.Wait()

		err = node.writeRequestNumber(ctx, store.SolanaScanHeightKey, offset+1)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) solanaReadBlock(ctx context.Context, checkpoint int64) error {
	client := node.SolanaClient()
	block, err := client.RPCGetBlockByHeight(ctx, uint64(checkpoint))
	if err != nil {
		if strings.Contains(err.Error(), "was skipped, or missing") {
			return nil
		}
		return err
	}

	for _, tx := range block.Transactions {
		err := node.solanaProcessTransaction(ctx, tx.MustGetTransaction(), tx.Meta)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) solanaProcessTransaction(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta) error {
	hash := tx.Signatures[0]
	call, err := node.store.ReadSystemCallByHash(ctx, hash.String())
	if err != nil {
		panic(err)
	}
	var exception *solana.PublicKey
	if call != nil {
		user := node.getUserSolanaPublicKeyFromCall(ctx, call)
		exception = &user
	}

	err = node.processTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		if strings.Contains(err.Error(), "get account info: not found") {
			return nil
		}
		panic(err)
	}
	// all balance changes from the creator account of a system call is handled in processSuccessedCall
	// only process deposits to other user accounts here
	transfers, err := node.SolanaClient().ExtractTransfersFromTransaction(ctx, tx, meta, exception)
	if err != nil {
		panic(err)
	}
	changes, err := node.parseSolanaBlockBalanceChanges(ctx, transfers)
	if err != nil {
		logger.Printf("node.parseSolanaBlockBalanceChanges(%s %d) => %d %v", hash.String(), len(transfers), len(changes), err)
		return err
	}
	if len(changes) == 0 {
		return nil
	}

	rentExemptBalance, err := node.RPCGetMinimumBalanceForRentExemption(
		ctx,
		solanaApp.NormalAccountSize,
		rpc.CommitmentConfirmed,
	)
	if err != nil {
		panic(err)
	}

	tsMap := make(map[string][]*solanaApp.TokenTransfers)
	for _, transfer := range transfers {
		key := fmt.Sprintf("%s:%s", transfer.Receiver, transfer.TokenAddress)
		if _, ok := changes[key]; !ok {
			continue
		}
		decimal := uint8(9)
		if transfer.TokenAddress != solanaApp.SolanaEmptyAddress {
			asset, err := node.RPCGetAsset(ctx, transfer.TokenAddress)
			if err != nil {
				logger.Printf("solana.RPCGetAsset(%s) => %v", transfer.TokenAddress, err)
				return err
			}
			decimal = uint8(asset.Decimals)
		}
		if transfer.TokenAddress == solanaApp.SolanaEmptyAddress {
			if transfer.Value.Uint64() == 1 {
				continue
			}
			index, err := tx.GetAccountIndex(solana.MustPublicKeyFromBase58(transfer.Receiver))
			if err != nil {
				panic(err)
			}
			if meta.PreBalances[index] <= rentExemptBalance {
				continue
			}
		}
		tsMap[transfer.Receiver] = append(tsMap[transfer.Receiver], &solanaApp.TokenTransfers{
			SolanaAsset: true,
			AssetId:     transfer.AssetId,
			ChainId:     solanaApp.SolanaChainBase,
			Mint:        solana.MustPublicKeyFromBase58(transfer.TokenAddress),
			Destination: node.solanaDepositEntry(),
			Amount:      transfer.Value.Uint64(),
			Decimals:    decimal,
		})
	}
	for user, ts := range tsMap {
		err = node.solanaProcessDepositTransaction(ctx, hash, user, ts)
		if err != nil {
			logger.Printf("node.solanaProcessDepositTransaction(%s) => %v", hash, err)
			return err
		}
	}
	return nil
}

func (node *Node) solanaProcessDepositTransaction(ctx context.Context, depositHash solana.Signature, user string, ts []*solanaApp.TokenTransfers) error {
	id := common.UniqueId(depositHash.String(), user)
	cid := common.UniqueId(id, "deposit")
	extra := solana.MustPublicKeyFromBase58(user).Bytes()
	extra = append(extra, depositHash[:]...)

	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil {
		return err
	}
	err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, cid)
	if err != nil {
		return err
	}
	tx, err := node.SolanaClient().TransferOrBurnTokens(ctx, node.SolanaPayer(), solana.MustPublicKeyFromBase58(user), nonce.Account(), ts)
	if err != nil {
		panic(err)
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	extra = attachSystemCall(extra, cid, data)

	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeDeposit,
		Extra: extra,
	}, nil)
}

func (node *Node) InitializeAccount(ctx context.Context, user *store.User) error {
	tx, err := node.SolanaClient().InitializeAccount(ctx, node.conf.SolanaKey, user.ChainAddress)
	if err != nil {
		return err
	}
	_, err = node.SendTransactionUtilConfirm(ctx, tx, nil, false)
	return err
}

func (node *Node) CreateMintsTransaction(ctx context.Context, as []string) (string, *solana.Transaction, []*solanaApp.DeployedAsset, error) {
	tid := fmt.Sprintf("OBSERVER:%s:MEMBERS:%v:%d", node.id, node.GetMembers(), node.conf.MTG.Genesis.Threshold)
	var assets []*solanaApp.DeployedAsset
	if common.CheckTestEnvironment(ctx) {
		tid = common.UniqueId(tid, common.SafeLitecoinChainId)
		ltc, err := common.SafeReadAssetUntilSufficient(ctx, common.SafeLitecoinChainId)
		if err != nil {
			panic(err)
		}
		key, err := solana.NewRandomPrivateKey()
		if err != nil {
			panic(err)
		}
		assets = []*solanaApp.DeployedAsset{
			{
				AssetId:    ltc.AssetID,
				Address:    "EFShFtXaMF1n1f6k3oYRd81tufEXzUuxYM6vkKrChVs8",
				Uri:        "https://uploads.mixin.one/mixin/attachments/1739005826-2dc1afa3f3327f4d29cbb02e3b41cf57d4842f3c444e8e829871699ac43d21b2",
				PrivateKey: &key,
				Asset:      ltc,
			},
		}
	} else {
		for _, asset := range as {
			na, err := common.SafeReadAssetUntilSufficient(ctx, asset)
			if err != nil {
				return "", nil, nil, err
			}
			uri, err := node.checkExternalAssetUri(ctx, na)
			if err != nil {
				return "", nil, nil, err
			}
			tid = common.UniqueId(tid, fmt.Sprintf("metadata-%s", asset))
			key := solanaApp.GenerateKeyForExternalAsset(node.GetMembers(), node.conf.MTG.Genesis.Threshold, asset)
			assets = append(assets, &solanaApp.DeployedAsset{
				AssetId:    asset,
				Address:    key.PublicKey().String(),
				Uri:        uri,
				Asset:      na,
				PrivateKey: &key,
			})
		}
	}

	for {
		call, err := node.store.ReadSystemCallByRequestId(ctx, tid, 0)
		if err != nil {
			return "", nil, nil, fmt.Errorf("store.ReadSystemCallByRequestId(%s) => %v %v", tid, call, err)
		}
		if call == nil {
			break
		}
		if call.State == common.RequestStateFailed {
			tid = common.UniqueId(tid, "retry")
			continue
		}
		return "", nil, nil, nil
	}
	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil || nonce == nil {
		return "", nil, nil, fmt.Errorf("store.ReadSpareNonceAccount(%s) => %v %v", tid, nonce, err)
	}
	err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, tid)
	if err != nil {
		return "", nil, nil, err
	}
	tx, err := node.SolanaClient().CreateMints(ctx, node.SolanaPayer(), node.getMTGAddress(ctx), nonce.Account(), assets)
	if err != nil {
		return "", nil, nil, err
	}
	return tid, tx, assets, nil
}

func (node *Node) CreateNonceAccount(ctx context.Context, index int) (string, string, error) {
	id := fmt.Sprintf("OBSERVER:%s:MEMBERS:%v:%d", node.id, node.GetMembers(), node.conf.MTG.Genesis.Threshold)
	id = common.UniqueId(id, fmt.Sprintf("computer nonce account: %d", index))
	seed := crypto.Sha256Hash(uuid.Must(uuid.FromString(id)).Bytes())
	nonce := solanaApp.PrivateKeyFromSeed(seed[:])

	tx, err := node.SolanaClient().CreateNonceAccount(ctx, node.conf.SolanaKey, nonce.String())
	if err != nil {
		return "", "", err
	}
	_, err = node.SendTransactionUtilConfirm(ctx, tx, nil, false)
	if err != nil {
		return "", "", err
	}
	for {
		hash, err := node.SolanaClient().GetNonceAccountHash(ctx, nonce.PublicKey())
		if err != nil {
			return "", "", err
		}
		if hash == nil {
			time.Sleep(5 * time.Second)
			continue
		}
		return nonce.PublicKey().String(), hash.String(), nil
	}
}

func (node *Node) CreatePrepareTransaction(ctx context.Context, call *store.SystemCall, nonce *store.NonceAccount, fee *store.SpentReference) (*solana.Transaction, error) {
	var transfers []solanaApp.TokenTransfers
	rs, _, err := node.GetSystemCallReferenceTxs(ctx, call.RequestHash)
	if err != nil {
		return nil, fmt.Errorf("node.GetSystemCallReferenceTxs(%s) => %v", call.RequestId, err)
	}
	if fee != nil {
		rs = append(rs, fee)
	}
	if len(rs) == 0 {
		return nil, nil
	}

	mtg := node.getMTGAddress(ctx)
	user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
	if err != nil || user == nil {
		return nil, fmt.Errorf("store.ReadUser(%s) => %s %v", call.UserIdFromPublicPath().String(), user, err)
	}
	destination := solana.MustPublicKeyFromBase58(user.ChainAddress)
	assets := node.GetSystemCallRelatedAsset(ctx, rs)
	for _, asset := range assets {
		amount := asset.Amount.Mul(decimal.New(1, int32(asset.Decimal)))
		mint := solana.MustPublicKeyFromBase58(asset.Address)
		if asset.Solana {
			transfers = append(transfers, solanaApp.TokenTransfers{
				SolanaAsset: true,
				AssetId:     asset.AssetId,
				ChainId:     asset.ChainId,
				Mint:        mint,
				Destination: destination,
				Amount:      amount.BigInt().Uint64(),
				Decimals:    uint8(asset.Decimal),
				Fee:         asset.Fee,
			})
			continue
		}
		transfers = append(transfers, solanaApp.TokenTransfers{
			SolanaAsset: false,
			AssetId:     asset.AssetId,
			ChainId:     asset.ChainId,
			Mint:        mint,
			Destination: destination,
			Amount:      amount.BigInt().Uint64(),
			Decimals:    uint8(asset.Decimal),
		})
	}
	if len(transfers) == 0 {
		return nil, nil
	}

	if common.CheckTestEnvironment(ctx) {
		sort.Slice(transfers, func(i, j int) bool {
			if transfers[i].AssetId > transfers[j].AssetId {
				return true
			}
			if transfers[i].Amount == transfers[j].Amount {
				return transfers[i].Amount > transfers[j].Amount
			}
			return false
		})
	}

	return node.SolanaClient().TransferOrMintTokens(ctx, node.SolanaPayer(), mtg, nonce.Account(), transfers)
}

func (node *Node) CreatePostprocessTransaction(ctx context.Context, call *store.SystemCall, nonce *store.NonceAccount, tx *solana.Transaction, meta *rpc.TransactionMeta) *solana.Transaction {
	rs, _, err := node.GetSystemCallReferenceTxs(ctx, call.RequestHash)
	if err != nil {
		panic(fmt.Errorf("node.GetSystemCallReferenceTxs(%s) => %v", call.RequestId, err))
	}
	assets := node.GetSystemCallRelatedAsset(ctx, rs)
	am := make(map[string]*ReferencedTxAsset)
	for _, a := range assets {
		am[a.Address] = a
	}
	assets = am

	user := node.getUserSolanaPublicKeyFromCall(ctx, call)
	if tx != nil && meta != nil {
		changes := node.buildUserBalanceChangesFromMeta(ctx, tx, meta, user)
		for address, change := range changes {
			old := assets[address]
			if old != nil {
				assets[address].Amount = assets[address].Amount.Add(change.Amount)
				continue
			}

			if !change.Amount.IsPositive() {
				if address == solanaApp.SolanaEmptyAddress {
					continue
				}
				panic(fmt.Errorf("invalid change for system call: %s %s %v", tx.Signatures[0].String(), call.RequestId, change))
			}
			da, err := node.store.ReadDeployedAssetByAddress(ctx, address)
			if err != nil {
				panic(fmt.Errorf("store.ReadDeployedAssetByAddress(%s) => %v %v", address, da, err))
			}
			isSolAsset := true
			assetId := ethereum.BuildChainAssetId(solanaApp.SolanaChainBase, address)
			if address == solanaApp.SolanaEmptyAddress {
				assetId = solanaApp.SolanaChainBase
			}
			chainId := solanaApp.SolanaChainBase
			if da != nil {
				isSolAsset = false
				assetId = da.AssetId
				chainId = da.ChainId
			}
			assets[address] = &ReferencedTxAsset{
				Solana:  isSolAsset,
				Address: address,
				Decimal: int(change.Decimals),
				Amount:  change.Amount,
				AssetId: assetId,
				ChainId: chainId,
			}
		}
	}

	var transfers []*solanaApp.TokenTransfers
	for _, asset := range assets {
		if asset.Amount.IsZero() {
			continue
		}
		amount := asset.Amount.Mul(decimal.New(1, int32(asset.Decimal)))
		mint := solana.MustPublicKeyFromBase58(asset.Address)
		if asset.Solana {
			transfers = append(transfers, &solanaApp.TokenTransfers{
				SolanaAsset: true,
				AssetId:     asset.AssetId,
				ChainId:     asset.ChainId,
				Mint:        mint,
				Destination: solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry),
				Amount:      amount.BigInt().Uint64(),
				Decimals:    uint8(asset.Decimal),
			})
			continue
		}
		transfers = append(transfers, &solanaApp.TokenTransfers{
			SolanaAsset: false,
			AssetId:     asset.AssetId,
			ChainId:     asset.ChainId,
			Mint:        mint,
			Destination: solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry),
			Amount:      amount.BigInt().Uint64(),
			Decimals:    uint8(asset.Decimal),
		})
	}
	if len(transfers) == 0 {
		return nil
	}

	if common.CheckTestEnvironment(ctx) {
		sort.Slice(transfers, func(i, j int) bool { return transfers[i].AssetId > transfers[j].AssetId })
	}

	tx, err = node.SolanaClient().TransferOrBurnTokens(ctx, node.SolanaPayer(), user, nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	return tx
}

func (node *Node) ReleaseLockedNonceAccount(ctx context.Context, nonce *store.NonceAccount) error {
	logger.Printf("observer.ReleaseLockedNonceAccount(%s)", nonce.Address)
	hash, err := node.SolanaClient().GetNonceAccountHash(ctx, nonce.Account().Address)
	if err != nil {
		panic(err)
	}
	if hash.String() != nonce.Hash {
		panic(fmt.Errorf("observer.ReleaseLockedNonceAccount(%s) => inconsistent hash %s %s ", nonce.Address, nonce.Hash, hash.String()))
	}
	return node.store.ReleaseLockedNonceAccount(ctx, nonce.Address)
}

type BalanceChange struct {
	Amount   decimal.Decimal
	Decimals uint8
}

// processTransactionWithAddressLookups resolves the address lookups in the transaction.
func (node *Node) processTransactionWithAddressLookups(ctx context.Context, txx *solana.Transaction) error {
	if txx.Message.IsResolved() {
		return nil
	}

	if !txx.Message.IsVersioned() {
		// tx is not versioned, ignore
		return nil
	}

	tblKeys := txx.Message.GetAddressTableLookups().GetTableIDs()
	if len(tblKeys) == 0 {
		return nil
	}
	numLookups := txx.Message.GetAddressTableLookups().NumLookups()
	if numLookups == 0 {
		return nil
	}

	resolutions := make(map[solana.PublicKey]solana.PublicKeySlice)
	for _, key := range tblKeys {
		info, err := node.RPCGetAccountInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("get account info: %w", err)
		}

		tableContent, err := lookup.DecodeAddressLookupTableState(info.GetBinary())
		if err != nil {
			return fmt.Errorf("decode address lookup table state: %w", err)
		}

		resolutions[key] = tableContent.Addresses
	}

	if err := txx.Message.SetAddressTables(resolutions); err != nil {
		return fmt.Errorf("set address tables: %w", err)
	}

	if err := txx.Message.ResolveLookups(); err != nil {
		return fmt.Errorf("resolve lookups: %w", err)
	}

	return nil
}

func (node *Node) buildUserBalanceChangesFromMeta(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta, user solana.PublicKey) map[string]*BalanceChange {
	err := node.processTransactionWithAddressLookups(ctx, tx)
	if err != nil {
		panic(err)
	}
	as, err := tx.AccountMetaList()
	if err != nil {
		panic(err)
	}

	changes := make(map[string]*BalanceChange)
	for index, account := range as {
		if !account.PublicKey.Equals(user) {
			continue
		}
		change := decimal.NewFromUint64(meta.PostBalances[index]).Sub(decimal.NewFromUint64(meta.PreBalances[index]))
		change = change.Div(decimal.New(1, 9))
		changes[solanaApp.SolanaEmptyAddress] = &BalanceChange{
			Amount:   change,
			Decimals: 9,
		}
	}

	preMap := buildBalanceMap(meta.PreTokenBalances, user)
	postMap := buildBalanceMap(meta.PostTokenBalances, user)
	for address, tb := range preMap {
		post := postMap[address]
		if post == nil {
			changes[address] = &BalanceChange{
				Amount:   tb.Amount.Neg(),
				Decimals: tb.Decimals,
			}
			continue
		}
		amount := post.Amount.Sub(tb.Amount)
		changes[address] = &BalanceChange{
			Amount:   amount,
			Decimals: tb.Decimals,
		}
	}
	for address, c := range postMap {
		if changes[address] != nil {
			continue
		}
		changes[address] = c
	}
	return changes
}

func buildBalanceMap(balances []rpc.TokenBalance, owner solana.PublicKey) map[string]*BalanceChange {
	bm := make(map[string]*BalanceChange)
	for _, tb := range balances {
		if !tb.Owner.Equals(owner) {
			continue
		}
		amount, err := decimal.NewFromString(tb.UiTokenAmount.UiAmountString)
		if err != nil {
			panic(err)
		}
		bm[tb.Mint.String()] = &BalanceChange{
			Amount:   amount,
			Decimals: tb.UiTokenAmount.Decimals,
		}
	}
	return bm
}

func (node *Node) SendTransactionUtilConfirm(ctx context.Context, tx *solana.Transaction, call *store.SystemCall, finalized bool) (*rpc.GetTransactionResult, error) {
	id := ""
	if call != nil {
		id = call.RequestId
	}

	hash := tx.Signatures[0].String()
	retry := SolanaTxRetry
	for {
		rpcTx, err := node.RPCGetTransaction(ctx, hash, finalized)
		if err != nil {
			return nil, fmt.Errorf("solana.RPCGetTransaction(%s) => %v", hash, err)
		}
		if rpcTx != nil {
			return rpcTx, nil
		}

		sig, sendError := node.SolanaClient().SendTransaction(ctx, tx)
		logger.Printf("solana.SendTransaction(%s) => %s %v", id, sig, sendError)
		if sendError == nil {
			retry -= 1
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if strings.Contains(sendError.Error(), "Blockhash not found") {
			// retry when observer send tx without nonce account
			if call == nil {
				retry -= 1
				if retry > 0 {
					time.Sleep(5 * time.Second)
					continue
				}
				return nil, sendError
			}

			// outdated nonce account hash when sending tx at first time
			if retry == SolanaTxRetry {
				return nil, sendError
			}
		}

		rpcTx, err = node.RPCGetTransaction(ctx, hash, false)
		logger.Printf("solana.RPCGetTransaction(%s) => %v", hash, err)
		if err != nil {
			return nil, fmt.Errorf("solana.RPCGetTransaction(%s) => %v", hash, err)
		}
		// transaction confirmed after re-sending failure
		if rpcTx != nil {
			if finalized {
				return node.RPCGetTransaction(ctx, hash, finalized)
			}
			return rpcTx, nil
		}

		retry -= 1
		if retry > 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return nil, sendError
	}
}

func (node *Node) VerifySubSystemCall(ctx context.Context, tx *solana.Transaction, groupDepositEntry, user solana.PublicKey) error {
	if common.CheckTestEnvironment(ctx) {
		return nil
	}
	for index, ix := range tx.Message.Instructions {
		programKey, err := tx.Message.Program(ix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		accounts, err := ix.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			panic(err)
		}

		if index == 0 {
			_, err := solanaApp.DecodeNonceAdvance(accounts, ix.Data)
			if err != nil {
				return fmt.Errorf("invalid nonce advance instruction: %v", err)
			}
			continue
		}

		switch programKey {
		case system.ProgramID:
			if _, ok := solanaApp.DecodeCreateAccount(accounts, ix.Data); ok {
				continue
			}
			if transfer, ok := solanaApp.DecodeSystemTransfer(accounts, ix.Data); ok {
				recipient := transfer.GetRecipientAccount().PublicKey
				if !recipient.Equals(groupDepositEntry) && !recipient.Equals(user) {
					return fmt.Errorf("invalid system transfer recipient: %s", recipient.String())
				}
				continue
			}
			return fmt.Errorf("invalid system program instruction: %d", index)
		case solana.TokenProgramID, solana.Token2022ProgramID:
			if mint, ok := solanaApp.DecodeTokenMintTo(accounts, ix.Data); ok {
				to := mint.GetDestinationAccount().PublicKey
				token := mint.GetMintAccount().PublicKey
				ata, _, err := solanaApp.FindAssociatedTokenAddress(user, token, programKey)
				if err != nil {
					return err
				}
				if !to.Equals(ata) {
					return fmt.Errorf("invalid mint to destination: %s", to.String())
				}
				continue
			}
			if transfer, ok := solanaApp.DecodeTokenTransferChecked(accounts, ix.Data); ok {
				recipient := transfer.GetDestinationAccount().PublicKey
				token := transfer.GetMintAccount().PublicKey
				entryAta, _, err := solanaApp.FindAssociatedTokenAddress(groupDepositEntry, token, programKey)
				if err != nil {
					return err
				}
				userAta, _, err := solanaApp.FindAssociatedTokenAddress(user, token, programKey)
				if err != nil {
					return err
				}
				if !recipient.Equals(entryAta) && !recipient.Equals(userAta) {
					return fmt.Errorf("invalid token transfer recipient: %s", recipient.String())
				}
				continue
			}
			if burn, ok := solanaApp.DecodeTokenBurn(accounts, ix.Data); ok {
				owner := burn.GetOwnerAccount().PublicKey
				if !owner.Equals(user) {
					return fmt.Errorf("invalid token burn owners: %s", owner.String())
				}
				continue
			}
			return fmt.Errorf("invalid token program instruction: %d", index)
		case tokenAta.ProgramID, solana.ComputeBudget:
		default:
			return fmt.Errorf("invalid program key: %s", programKey.String())
		}
	}
	return nil
}

func (node *Node) VerifyMintSystemCall(ctx context.Context, tx *solana.Transaction, mtgAccount solana.PublicKey, as map[string]*solanaApp.DeployedAsset) error {
	for index, ix := range tx.Message.Instructions {
		programKey, err := tx.Message.Program(ix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		accounts, err := ix.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			panic(err)
		}

		if index == 0 {
			_, err := solanaApp.DecodeNonceAdvance(accounts, ix.Data)
			if err != nil {
				return fmt.Errorf("invalid nonce advance instruction: %v", err)
			}
			continue
		}

		switch programKey {
		case solana.TokenMetadataProgramID:
		case system.ProgramID:
			if _, ok := solanaApp.DecodeCreateAccount(accounts, ix.Data); ok {
				continue
			}
			return fmt.Errorf("invalid system program instruction: %d", index)
		case solana.TokenProgramID, solana.Token2022ProgramID:
			if mint, ok := solanaApp.DecodeMintToken(accounts, ix.Data); ok {
				address := mint.GetMintAccount().PublicKey
				asset := as[address.String()]
				if asset == nil {
					return fmt.Errorf("invalid token mint instruction: invalid address %s", address.String())
				}
				if int(*mint.Decimals) != asset.Asset.Precision {
					return fmt.Errorf("invalid token mint instruction: invalid decimals %d", mint.Decimals)
				}
				if mint.FreezeAuthority != nil {
					return fmt.Errorf("invalid token mint instruction: invalid freezeAuthority")
				}
				if !mint.MintAuthority.Equals(mtgAccount) {
					return fmt.Errorf("invalid token mint instruction: invalid mintAuthority %s", mint.MintAuthority)
				}
				continue
			}
			return fmt.Errorf("invalid token program instruction: %d", index)
		case solana.ComputeBudget:
		default:
			return fmt.Errorf("invalid program key: %s", programKey.String())
		}
	}
	return nil
}

func (node *Node) parseSolanaBlockBalanceChanges(ctx context.Context, transfers []*solanaApp.Transfer) (map[string]*big.Int, error) {
	mtgAddress := node.getMTGAddress(ctx).String()

	changes := make(map[string]*big.Int)
	for _, t := range transfers {
		if t.Receiver == solanaApp.SolanaEmptyAddress ||
			t.Sender == node.SolanaPayer().String() ||
			t.Sender == mtgAddress ||
			t.Receiver == mtgAddress {
			continue
		}

		user, err := node.store.ReadUserByChainAddress(ctx, t.Receiver)
		logger.Verbosef("store.ReadUserByAddress(%s) => %v %v", t.Receiver, user, err)
		if err != nil {
			return nil, err
		} else if user == nil {
			continue
		}
		token, err := node.store.ReadDeployedAssetByAddress(ctx, t.TokenAddress)
		if err != nil {
			return nil, err
		} else if token != nil {
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

func (node *Node) getUserSolanaPublicKeyFromCall(ctx context.Context, c *store.SystemCall) solana.PublicKey {
	data := common.DecodeHexOrPanic(c.Public)
	if len(data) != 16 {
		panic(fmt.Errorf("invalid public of system call: %s %s", c.RequestId, c.Public))
	}
	fp, path := hex.EncodeToString(data[:8]), data[8:]
	_, share, err := node.store.ReadKeyByFingerprint(ctx, fp)
	if err != nil {
		panic(err)
	}
	pub, _ := node.deriveByPath(share, path)
	return solana.PublicKeyFromBytes(pub)
}

func (node *Node) SolanaClient() *solanaApp.Client {
	return solanaApp.NewClient(node.conf.SolanaRPC)
}

func (node *Node) RPCGetTransaction(ctx context.Context, signature string, finalized bool) (*rpc.GetTransactionResult, error) {
	key := fmt.Sprintf("getTransaction:%s:%t", signature, finalized)
	value, err := node.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}

	if value != "" {
		var r rpc.GetTransactionResult
		err = json.Unmarshal(common.DecodeHexOrPanic(value), &r)
		if err != nil {
			panic(err)
		}
		return &r, nil
	}

	tx, err := node.SolanaClient().RPCGetTransaction(ctx, signature, finalized)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(tx)
	if err != nil {
		panic(err)
	}
	err = node.store.WriteCache(ctx, key, hex.EncodeToString(b))
	if err != nil {
		panic(err)
	}
	return tx, nil
}

func (node *Node) RPCGetAccount(ctx context.Context, account solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	key := fmt.Sprintf("getAccountInfo:%s", account.String())
	value, err := node.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}

	if value != "" {
		var r rpc.GetAccountInfoResult
		err = json.Unmarshal(common.DecodeHexOrPanic(value), &r)
		if err != nil {
			panic(err)
		}
		return &r, nil
	}

	acc, err := node.SolanaClient().RPCGetAccount(ctx, account)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(acc)
	if err != nil {
		panic(err)
	}
	err = node.store.WriteCache(ctx, key, hex.EncodeToString(b))
	if err != nil {
		panic(err)
	}
	return acc, nil
}

func (node *Node) RPCGetAccountInfo(ctx context.Context, account solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	key := fmt.Sprintf("getAccountInfo:%s", account.String())
	value, err := node.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}

	if value != "" {
		var r rpc.GetAccountInfoResult
		err = json.Unmarshal(common.DecodeHexOrPanic(value), &r)
		if err != nil {
			panic(err)
		}
		return &r, nil
	}

	acc, err := node.SolanaClient().RPCGetAccountInfo(ctx, account)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(acc)
	if err != nil {
		panic(err)
	}
	err = node.store.WriteCache(ctx, key, hex.EncodeToString(b))
	if err != nil {
		panic(err)
	}
	return acc, nil
}

func (node *Node) RPCGetAsset(ctx context.Context, account string) (*solanaApp.Asset, error) {
	key := fmt.Sprintf("getAsset:%s", account)
	value, err := node.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}

	if value != "" {
		var a solanaApp.Asset
		err = json.Unmarshal(common.DecodeHexOrPanic(value), &a)
		if err != nil {
			panic(err)
		}
		return &a, nil
	}

	asset, err := node.SolanaClient().RPCGetAsset(ctx, account)
	if err != nil {
		panic(err)
	}
	b, err := json.Marshal(asset)
	if err != nil {
		panic(err)
	}
	err = node.store.WriteCache(ctx, key, hex.EncodeToString(b))
	if err != nil {
		panic(err)
	}
	return asset, nil
}

func (node *Node) RPCGetMinimumBalanceForRentExemption(ctx context.Context, dataSize uint64, commitment rpc.CommitmentType) (uint64, error) {
	key := fmt.Sprintf("getMinimumBalanceForRentExemption:%d:%s", dataSize, commitment)
	value, err := node.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}

	if value != "" {
		rent, err := decimal.NewFromString(value)
		if err != nil {
			panic(err)
		}
		return rent.BigInt().Uint64(), nil
	}

	r, err := node.RPCGetMinimumBalanceForRentExemption(ctx, dataSize, commitment)
	if err != nil {
		panic(err)
	}
	err = node.store.WriteCache(ctx, key, fmt.Sprintf("%d", r))
	if err != nil {
		panic(err)
	}
	return r, nil
}

func (node *Node) SolanaPayer() solana.PublicKey {
	return solana.MustPrivateKeyFromBase58(node.conf.SolanaKey).PublicKey()
}

func (node *Node) getMTGAddress(ctx context.Context) solana.PublicKey {
	key, err := node.store.ReadFirstPublicKey(ctx)
	if err != nil || key == "" {
		panic(fmt.Errorf("store.ReadFirstPublicKey() => %s %v", key, err))
	}
	return solana.PublicKeyFromBytes(common.DecodeHexOrPanic(key))
}

func (node *Node) getMTGPublicWithPath(ctx context.Context) string {
	key, err := node.store.ReadFirstPublicKey(ctx)
	if err != nil || key == "" {
		panic(fmt.Errorf("store.ReadFirstPublicKey() => %s %v", key, err))
	}
	fp := common.Fingerprint(key)
	public := append(fp, store.DefaultPath...)
	return hex.EncodeToString(public)
}

func (node *Node) solanaDepositEntry() solana.PublicKey {
	return solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry)
}
