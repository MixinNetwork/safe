package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	solana "github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gofrs/uuid/v5"
)

const SolanaBlockDelay = 32

func (node *Node) solanaRPCBlocksLoop(ctx context.Context) {
	client := node.solanaClient()

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
		if checkpoint+SolanaBlockDelay > int64(height)+1 {
			logger.Printf("current %d > limit %d", checkpoint+SolanaBlockDelay, int64(height)+1)
			time.Sleep(time.Second * 5)
			continue
		}
		err = node.solanaReadBlock(ctx, checkpoint)
		logger.Printf("node.solanaReadBlock(%d) => %v", checkpoint, err)
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}
		err = node.writeRequestNumber(ctx, store.SolanaScanHeightKey, checkpoint+1)
		if err != nil {
			panic(err)
		}
	}
}

func (node *Node) solanaReadBlock(ctx context.Context, checkpoint int64) error {
	client := node.solanaClient()
	block, err := client.RPCGetBlockByHeight(ctx, uint64(checkpoint))
	if err != nil {
		if strings.Contains(err.Error(), "was skipped, or missing in long-term storage") {
			i := 1
			for {
				next, er := client.RPCGetBlockByHeight(ctx, uint64(checkpoint+int64(i)))
				if er != nil {
					if strings.Contains(err.Error(), "was skipped, or missing in long-term storage") {
						i += 1
						time.Sleep(time.Second)
						continue
					}
					return er
				}
				if next.ParentSlot != uint64(checkpoint) {
					return nil
				}
			}
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
	err := node.solanaProcessCallTransaction(ctx, tx)
	if err != nil {
		logger.Printf("node.solanaProcessCallTransaction(%s) => %v", tx.Signatures[0].String(), err)
		return err
	}

	transfers, err := node.solanaClient().ExtractTransfersFromTransaction(ctx, tx, meta)
	if err != nil {
		panic(err)
	}
	changes, err := node.parseSolanaBlockBalanceChanges(ctx, transfers)
	if err != nil || len(changes) == 0 {
		logger.Printf("node.parseSolanaBlockBalanceChanges(%d) => %d %v", len(transfers), len(changes), err)
		return err
	}
	tsMap := make(map[string][]*solanaApp.TokenTransfers)
	for _, transfer := range transfers {
		key := fmt.Sprintf("%s:%s", transfer.Receiver, transfer.TokenAddress)
		if _, ok := changes[key]; !ok {
			continue
		}
		decimal := uint8(9)
		if transfer.TokenAddress != solanaApp.SolanaEmptyAddress {
			asset, err := node.solanaClient().RPCGetAsset(ctx, transfer.TokenAddress)
			if err != nil {
				return err
			}
			decimal = uint8(asset.Decimals)
		}
		tsMap[transfer.Receiver] = append(tsMap[transfer.Receiver], &solanaApp.TokenTransfers{
			SolanaAsset: true,
			AssetId:     solanaApp.GenerateAssetId(transfer.TokenAddress),
			ChainId:     solanaApp.SolanaChainBase,
			Mint:        solana.MustPublicKeyFromBase58(transfer.TokenAddress),
			Destination: node.solanaDepositEntry(),
			Amount:      transfer.Value.Uint64(),
			Decimals:    decimal,
		})
	}
	hash := tx.Signatures[0]
	for user, ts := range tsMap {
		err = node.solanaProcessDepositTransaction(ctx, hash, user, ts)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) solanaProcessCallTransaction(ctx context.Context, tx *solana.Transaction) error {
	signedBy := tx.Message.IsSigner(node.solanaPayer())
	if !signedBy {
		return nil
	}

	message, err := tx.Message.MarshalBinary()
	if err != nil {
		panic(err)
	}
	call, err := node.store.ReadSystemCallByMessage(ctx, hex.EncodeToString(message))
	if err != nil {
		panic(err)
	}
	if call == nil {
		return nil
	}
	nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
	if err != nil || nonce == nil {
		panic(err)
	}

	txId := tx.Signatures[0]
	newNonceHash, err := node.solanaClient().GetNonceAccountHash(ctx, nonce.Account().Address)
	if err != nil {
		panic(err)
	}
	err = node.store.UpdateNonceAccount(ctx, nonce.Address, newNonceHash.String())
	if err != nil {
		panic(err)
	}

	id := common.UniqueId(txId.String(), "confirm-call")
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, txId[:]...)
	err = node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
		Extra: extra,
	})
	if err != nil {
		return err
	}
	if call.Type != store.CallTypeMain || call.SkipPostprocess {
		return nil
	}

	nonce, err = node.store.ReadSpareNonceAccount(ctx)
	if err != nil {
		return err
	}
	source := node.getUserSolanaPublicKeyFromCall(ctx, call)
	tx = node.burnRestTokens(ctx, call, source, nonce)
	if tx == nil {
		return nil
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	id = common.UniqueId(call.RequestId, "post-tx-storage")
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, id, *node.safeUser())
	if err != nil {
		return err
	}

	id = common.UniqueId(id, "craete-post-call")
	extra = uuid.Must(uuid.FromString(call.RequestId)).Bytes()
	extra = append(extra, nonce.Account().Address.Bytes()...)
	extra = append(extra, hash[:]...)
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeCreateSubCall,
		Extra: extra,
	})
}

func (node *Node) solanaProcessDepositTransaction(ctx context.Context, depositHash solana.Signature, user string, ts []*solanaApp.TokenTransfers) error {
	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil {
		return err
	}
	tx := node.transferRestTokens(ctx, solana.MustPublicKeyFromBase58(user), nonce, ts)
	if tx == nil {
		return nil
	}
	data, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	id := common.UniqueId(depositHash.String(), user)
	id = common.UniqueId(id, "deposit")
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, id, *node.safeUser())
	if err != nil {
		return err
	}

	id = common.UniqueId(id, "craete-deposit-call")
	extra := solana.MustPublicKeyFromBase58(user).Bytes()
	extra = append(extra, nonce.Account().Address.Bytes()...)
	extra = append(extra, hash[:]...)
	return node.sendObserverTransactionToGroup(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeDeposit,
		Extra: extra,
	})
}

func (node *Node) CreateMintsTransaction(ctx context.Context, as []string, nonce *store.NonceAccount) (string, *solana.Transaction, []*solanaApp.DeployedAsset, error) {
	tid := fmt.Sprintf("OBSERVER:%s:MEMBERS:%v:%d", node.id, node.GetMembers(), node.conf.MTG.Genesis.Threshold)
	var assets []*solanaApp.DeployedAsset
	if common.CheckTestEnvironment(ctx) {
		tid = common.UniqueId(tid, common.SafeLitecoinChainId)
		ltc, err := bot.ReadAsset(ctx, common.SafeLitecoinChainId)
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
			tid = common.UniqueId(tid, asset)
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

	call, err := node.store.ReadSystemCallByRequestId(ctx, tid, 0)
	if err != nil {
		return "", nil, nil, fmt.Errorf("store.ReadSystemCallByRequestId(%s) => %v %v", tid, call, err)
	}
	if call != nil {
		return "", nil, nil, nil
	}
	err = node.store.OccupyNonceAccountByCall(ctx, nonce.Address, tid)
	if err != nil {
		return "", nil, nil, err
	}
	tx, err := node.solanaClient().CreateMints(ctx, node.solanaPayer(), node.getMTGAddress(ctx), nonce.Account(), assets)
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

	tx, err := node.solanaClient().CreateNonceAccount(ctx, node.conf.SolanaKey, nonce.String())
	if err != nil {
		return "", "", err
	}
	err = node.SendTransactionUtilConfirm(ctx, tx)
	if err != nil {
		return "", "", err
	}
	for {
		hash, err := node.solanaClient().GetNonceAccountHash(ctx, nonce.PublicKey())
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

func (node *Node) SendTransactionUtilConfirm(ctx context.Context, tx *solana.Transaction) error {
	var h string
	for {
		sig, err := node.solanaClient().SendTransaction(ctx, tx)
		if err == nil {
			h = sig
			break
		}
		if strings.Contains(err.Error(), "Blockhash not found") {
			time.Sleep(1 * time.Second)
			continue
		}
		return err
	}
	for {
		rpcTx, err := node.solanaClient().RPCGetTransaction(ctx, h)
		if rpcTx != nil {
			break
		}
		if strings.Contains(err.Error(), "not found") {
			time.Sleep(1 * time.Second)
			continue
		}
		return fmt.Errorf("solana.RPCGetTransaction(%s) => %v", h, err)
	}
	return nil
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
			_, ok := solanaApp.DecodeNonceAdvance(accounts, ix.Data)
			if !ok {
				return fmt.Errorf("invalid nonce advance instruction")
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
			}
			return fmt.Errorf("invalid system program instruction: %d", index)
		case solana.TokenProgramID, solana.Token2022ProgramID:
			if mint, ok := solanaApp.DecodeTokenMintTo(accounts, ix.Data); ok {
				to := mint.GetDestinationAccount().PublicKey
				token := mint.GetMintAccount().PublicKey
				ata, _, err := solana.FindAssociatedTokenAddress(user, token)
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
				entryAta, _, err := solana.FindAssociatedTokenAddress(groupDepositEntry, token)
				if err != nil {
					return err
				}
				userAta, _, err := solana.FindAssociatedTokenAddress(user, token)
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
		case tokenAta.ProgramID:
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
			_, ok := solanaApp.DecodeNonceAdvance(accounts, ix.Data)
			if !ok {
				return fmt.Errorf("invalid nonce advance instruction")
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
		if t.Receiver == solanaApp.SolanaEmptyAddress || t.Sender == mtgAddress || t.Receiver == mtgAddress {
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

func (node *Node) transferOrMintTokens(ctx context.Context, call *store.SystemCall, nonce *store.NonceAccount) (*solana.Transaction, error) {
	mtg := node.getMTGAddress(ctx)
	user, err := node.store.ReadUser(ctx, call.UserIdFromPublicPath())
	if err != nil || user == nil {
		return nil, fmt.Errorf("store.ReadUser(%s) => %s %v", call.UserIdFromPublicPath().String(), user, err)
	}
	destination := solana.MustPublicKeyFromBase58(user.ChainAddress)

	var transfers []solanaApp.TokenTransfers
	assets := node.GetSystemCallRelatedAsset(ctx, call.RequestId)
	for _, asset := range assets {
		if asset.Solana {
			mint := solana.MustPublicKeyFromBase58(asset.Asset.AssetKey)
			transfers = append(transfers, solanaApp.TokenTransfers{
				SolanaAsset: true,
				AssetId:     asset.Asset.AssetID,
				ChainId:     asset.Asset.ChainID,
				Mint:        mint,
				Destination: destination,
				Amount:      asset.Amount.BigInt().Uint64(),
				Decimals:    uint8(asset.Asset.Precision),
			})
			continue
		}
		da, err := node.store.ReadDeployedAsset(ctx, asset.Asset.AssetID, common.RequestStateDone)
		if err != nil || da == nil {
			return nil, fmt.Errorf("store.ReadDeployedAsset(%s) => %v %v", asset.Asset.AssetID, da, err)
		}
		transfers = append(transfers, solanaApp.TokenTransfers{
			SolanaAsset: false,
			AssetId:     asset.Asset.AssetID,
			ChainId:     asset.Asset.ChainID,
			Mint:        da.PublicKey(),
			Destination: destination,
			Amount:      asset.Amount.BigInt().Uint64(),
			Decimals:    uint8(asset.Asset.Precision),
		})
	}
	if len(transfers) == 0 {
		return nil, nil
	}

	return node.solanaClient().TransferOrMintTokens(ctx, node.solanaPayer(), mtg, nonce.Account(), transfers)
}

func (node *Node) burnRestTokens(ctx context.Context, main *store.SystemCall, source solana.PublicKey, nonce *store.NonceAccount) *solana.Transaction {
	assets := node.GetSystemCallRelatedAsset(ctx, main.RequestId)
	var externals []string
	as := make(map[string]string)
	for _, asset := range assets {
		if asset.Solana {
			continue
		}
		a, err := node.store.ReadDeployedAsset(ctx, asset.Asset.AssetID, common.RequestStateDone)
		if err != nil {
			panic(err)
		}
		externals = append(externals, a.Address)
		as[a.Address] = a.AssetId
	}
	if len(externals) == 0 {
		return nil
	}

	spls, err := node.solanaClient().RPCGetTokenAccountsByOwner(ctx, source)
	if err != nil {
		panic(err)
	}
	if common.CheckTestEnvironment(ctx) {
		spls = []*token.Account{
			{
				Mint:   solana.MustPublicKeyFromBase58("EFShFtXaMF1n1f6k3oYRd81tufEXzUuxYM6vkKrChVs8"),
				Amount: 1000000,
			},
		}
	}
	var transfers []*solanaApp.TokenTransfers
	for _, t := range spls {
		address := t.Mint.String()
		if !slices.Contains(externals, address) || t.Amount == 0 {
			continue
		}
		asset, err := common.SafeReadAssetUntilSufficient(ctx, as[address])
		if err != nil {
			panic(err)
		}
		transfer := &solanaApp.TokenTransfers{
			Mint:        t.Mint,
			Destination: solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry),
			Amount:      t.Amount,
			Decimals:    uint8(asset.Precision),
		}
		transfers = append(transfers, transfer)
	}
	if len(transfers) == 0 {
		return nil
	}

	return node.transferRestTokens(ctx, source, nonce, transfers)
}

func (node *Node) transferRestTokens(ctx context.Context, source solana.PublicKey, nonce *store.NonceAccount, transfers []*solanaApp.TokenTransfers) *solana.Transaction {
	tx, err := node.solanaClient().TransferOrBurnTokens(ctx, node.solanaPayer(), source, nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	return tx
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

func (node *Node) solanaClient() *solanaApp.Client {
	return solanaApp.NewClient(node.conf.SolanaRPC)
}

func (node *Node) solanaPayer() solana.PublicKey {
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
