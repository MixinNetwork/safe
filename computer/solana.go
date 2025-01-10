package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	solana "github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gofrs/uuid/v5"
)

const SolanaBlockDelay = 32

func (node *Node) solanaRPCBlocksLoop(ctx context.Context) {
	client := node.solanaClient()

	for {
		// FIXME synchronous block height checkpoint between observers
		var checkpoint int64
		height, _, err := client.RPCGetBlockHeight(ctx)
		if err != nil {
			logger.Printf("solana.RPCGetBlockHeight => %v", err)
			time.Sleep(time.Second * 5)
			continue
		}
		if checkpoint+SolanaBlockDelay > height+1 {
			time.Sleep(time.Second * 5)
			continue
		}
		err = node.solanaReadBlock(ctx, checkpoint)
		logger.Printf("node.solanaReadBlock(%d) => %v", checkpoint, err)
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
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
		return node.solanaProcessTransaction(ctx, tx.MustGetTransaction(), tx.Meta)
	}

	return nil
}

func (node *Node) solanaProcessTransaction(ctx context.Context, tx *solana.Transaction, meta *rpc.TransactionMeta) error {
	err := node.solanaProcessCallTransaction(ctx, tx)
	if err != nil {
		return err
	}

	hash := tx.Signatures[0]
	transfers, err := solanaApp.ExtractTransfersFromTransaction(ctx, tx, meta)
	if err != nil {
		return err
	}
	changes, err := node.parseSolanaBlockBalanceChanges(ctx, transfers)
	logger.Printf("node.parseSolanaBlockBalanceChanges(%d) => %d %v", len(transfers), len(changes), err)
	if err != nil || len(changes) == 0 {
		return err
	}
	tsMap := make(map[string][]*solanaApp.TokenTransfers)
	for _, transfer := range transfers {
		key := fmt.Sprintf("%s:%s", transfer.Receiver, transfer.TokenAddress)
		if _, ok := changes[key]; !ok {
			continue
		}
		decimal := uint8(9)
		if transfer.TokenAddress == "11111111111111111111111111111111" {
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
	for user, ts := range tsMap {
		err = node.solanaProcessDepositTransaction(ctx, hash, user, ts)
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) solanaProcessCallTransaction(ctx context.Context, tx *solana.Transaction) error {
	signedBy := tx.Message.IsSigner(node.solanaAccount())
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

	id := common.UniqueId(txId.String(), "confirm-call")
	extra := []byte{FlagConfirmCallSuccess}
	extra = append(extra, txId[:]...)
	extra = append(extra, newNonceHash[:]...)
	err = node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
		Extra: extra,
	})
	if err != nil {
		return err
	}

	if call.Type == store.CallTypeMain {
		nonce, err := node.store.ReadSpareNonceAccount(ctx)
		if err != nil {
			return err
		}
		tx := node.burnRestTokens(ctx, call, solanaApp.PublicKeyFromEd25519Public(call.Public), nonce)
		if tx == nil {
			return nil
		}
		data, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		id := common.UniqueId(call.RequestId, "post-tx-storage")
		hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, id, *node.safeUser())
		if err != nil {
			return err
		}

		id = common.UniqueId(id, "craete-post-call")
		extra := uuid.Must(uuid.FromString(call.RequestId)).Bytes()
		extra = append(extra, nonce.Account().Address.Bytes()...)
		extra = append(extra, hash[:]...)
		err = node.sendObserverTransaction(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeCreateSubCall,
			Extra: extra,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (node *Node) solanaProcessFailedCallTransaction(ctx context.Context, call *store.SystemCall) error {
	id := common.UniqueId(call.RequestId, "confirm-call-failed")
	extra := []byte{FlagConfirmCallFail}
	extra = append(extra, uuid.Must(uuid.FromString(call.RequestId)).Bytes()...)
	err := node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
		Extra: extra,
	})
	if err != nil {
		return err
	}

	if call.Type == store.CallTypeMain {
		nonce, err := node.store.ReadNonceAccount(ctx, call.NonceAccount)
		if err != nil {
			return err
		}
		tx := node.burnRestTokens(ctx, call, solanaApp.PublicKeyFromEd25519Public(call.Public), nonce)
		if tx == nil {
			return nil
		}
		data, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		id := common.UniqueId(call.RequestId, "post-tx-storage")
		hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, id, *node.safeUser())
		if err != nil {
			return err
		}

		id = common.UniqueId(id, "craete-post-call")
		extra := uuid.Must(uuid.FromString(call.RequestId)).Bytes()
		extra = append(extra, nonce.Account().Address.Bytes()...)
		extra = append(extra, hash[:]...)
		err = node.sendObserverTransaction(ctx, &common.Operation{
			Id:    id,
			Type:  OperationTypeCreateSubCall,
			Extra: extra,
		})
		if err != nil {
			return err
		}
	}

	return nil
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
	err = node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeDeposit,
		Extra: extra,
	})
	if err != nil {
		return err
	}

	return nil
}

func (node *Node) CreateNonceAccount(ctx context.Context) (*solana.PublicKey, *solana.Hash, error) {
	nonce, err := solana.NewRandomPrivateKey()
	if err != nil {
		panic(err)
	}

	client := node.solanaClient()
	tx, err := client.CreateNonceAccount(ctx, node.conf.SolanaKey, nonce.String(), "", 0)
	if err != nil {
		return nil, nil, err
	}
	err = client.SendAndConfirmTransaction(ctx, tx)
	if err != nil {
		return nil, nil, err
	}

	hash, err := client.GetNonceAccountHash(ctx, nonce.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	pub := nonce.PublicKey()

	return &pub, hash, nil
}

func (node *Node) VerifySubSystemCall(ctx context.Context, tx *solana.Transaction, groupDepositEntry, user, nonce solana.PublicKey) error {
	for _, ix := range tx.Message.Instructions {
		programKey, err := tx.Message.Program(ix.ProgramIDIndex)
		if err != nil {
			panic(err)
		}
		accounts, err := ix.ResolveInstructionAccounts(&tx.Message)
		if err != nil {
			panic(err)
		}

		switch programKey {
		case system.ProgramID:
			if transfer, ok := solanaApp.DecodeSystemTransfer(accounts, ix.Data); ok {
				recipient := transfer.GetRecipientAccount().PublicKey
				if !recipient.Equals(groupDepositEntry) && !recipient.Equals(user) {
					return fmt.Errorf("invalid system transfer recipient: %s", recipient.String())
				}
				continue
			}
			if advance, ok := solanaApp.DecodeNonceAdvance(accounts, ix.Data); ok {
				nonceAccount := advance.GetNonceAccount().PublicKey
				if !nonceAccount.Equals(nonce) {
					return fmt.Errorf("invalid nonce account: %s", nonce.String())
				}
			}
		case solana.TokenProgramID, solana.Token2022ProgramID:
			if mint, ok := solanaApp.DecodeTokenMint(accounts, ix.Data); ok {
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
		case tokenAta.ProgramID:
		default:
			return fmt.Errorf("invalid program key: %s", programKey.String())
		}
	}
	return nil
}

func (node *Node) parseSolanaBlockBalanceChanges(ctx context.Context, transfers []*solanaApp.Transfer) (map[string]*big.Int, error) {
	mtgUser, err := node.store.ReadUser(ctx, store.MPCUserId)
	if err != nil || mtgUser == nil {
		panic(err)
	}
	mtgAddress := solana.MustPublicKeyFromBase58(mtgUser.Public).String()

	changes := make(map[string]*big.Int)
	for _, t := range transfers {
		if t.Receiver == solanaApp.SolanaEmptyAddress || t.Sender == mtgAddress {
			continue
		}

		user, err := node.store.ReadUserByChainAddress(ctx, t.Receiver)
		logger.Verbosef("store.ReadUserByAddress(%s) => %v %v", t.Receiver, user, err)
		if err != nil {
			return nil, err
		} else if user == nil || user.UserId == mtgUser.UserId {
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

func (node *Node) transferOrMintTokens(ctx context.Context, call *store.SystemCall, nonce *store.NonceAccount) (*solana.Transaction, []*store.DeployedAsset) {
	user, err := node.store.ReadUserByPublic(ctx, call.Public)
	if err != nil {
		panic(err)
	}
	mtgUser, err := node.store.ReadUser(ctx, store.MPCUserId)
	if err != nil {
		panic(err)
	}
	destination := solanaApp.PublicKeyFromEd25519Public(user.Public)

	var transfers []solanaApp.TokenTransfers
	var as []*store.DeployedAsset
	assets := node.getSystemCallRelatedAsset(ctx, call.RequestId)
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
		da, err := node.store.ReadDeployedAsset(ctx, asset.Asset.AssetID)
		if err != nil {
			panic(err)
		}
		if da == nil {
			key, err := solana.NewRandomPrivateKey()
			if err != nil {
				panic(err)
			}
			da = &store.DeployedAsset{
				AssetId:    asset.Asset.AssetID,
				Address:    key.PublicKey().String(),
				PrivateKey: &key,
			}
			if common.CheckTestEnvironment(ctx) {
				da.Address = "EFShFtXaMF1n1f6k3oYRd81tufEXzUuxYM6vkKrChVs8"
				da.PrivateKey = nil
			}
			as = append(as, da)
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
	if len(transfers) == 0 || nonce == nil {
		return nil, as
	}

	tx, err := node.solanaClient().TransferOrMintTokens(ctx, node.solanaAccount(), mtgUser.PublicKey(), nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	for _, da := range as {
		if da.PrivateKey == nil {
			continue
		}
		_, err = tx.PartialSign(solanaApp.BuildSignersGetter(*da.PrivateKey))
		if err != nil {
			panic(err)
		}
	}
	return tx, as
}

func (node *Node) burnRestTokens(ctx context.Context, main *store.SystemCall, source solana.PublicKey, nonce *store.NonceAccount) *solana.Transaction {
	assets := node.getSystemCallRelatedAsset(ctx, main.RequestId)
	var externals []string
	for _, asset := range assets {
		if asset.Solana {
			continue
		}
		a, err := node.store.ReadDeployedAsset(ctx, asset.Asset.AssetID)
		if err != nil {
			panic(err)
		}
		externals = append(externals, a.Address)
	}
	if len(externals) == 0 {
		return nil
	}

	spls, err := node.solanaClient().RPCGetTokenAccountsByOwner(ctx, source)
	if err != nil {
		panic(err)
	}
	var transfers []*solanaApp.TokenTransfers
	for _, token := range spls {
		if !slices.Contains(externals, token.Mint.String()) || token.Amount == 0 {
			continue
		}
		transfer := &solanaApp.TokenTransfers{
			Mint:        token.Mint,
			Destination: solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry),
			Amount:      token.Amount,
			Decimals:    9,
		}
		transfers = append(transfers, transfer)
	}
	if len(transfers) == 0 {
		return nil
	}

	tx, err := node.solanaClient().TransferOrBurnTokens(ctx, node.solanaAccount(), source, nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	return tx
}

func (node *Node) transferRestTokens(ctx context.Context, source solana.PublicKey, nonce *store.NonceAccount, transfers []*solanaApp.TokenTransfers) *solana.Transaction {
	tx, err := node.solanaClient().TransferOrBurnTokens(ctx, node.solanaAccount(), source, nonce.Account(), transfers)
	if err != nil {
		panic(err)
	}
	return tx
}

func (node *Node) solanaClient() *solanaApp.Client {
	return solanaApp.NewClient(node.conf.SolanaRPC, node.conf.SolanaWsRPC)
}

func (node *Node) solanaAccount() solana.PublicKey {
	return solana.MustPrivateKeyFromBase58(node.conf.SolanaKey).PublicKey()
}

func (node *Node) solanaDepositEntry() solana.PublicKey {
	return solana.MustPublicKeyFromBase58(node.conf.SolanaDepositEntry)
}
