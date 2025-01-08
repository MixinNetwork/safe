package computer

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	solana "github.com/gagliardetto/solana-go"
	tokenAta "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/rpc"
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
		err := node.solanaProcessTransaction(ctx, tx)
		if err != nil {
			return err
		}
	}

	return nil
}

func (node *Node) solanaProcessTransaction(ctx context.Context, rpcTx rpc.TransactionWithMeta) error {
	tx := rpcTx.MustGetTransaction()
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
	extra := txId[:]
	extra = append(extra, newNonceHash[:]...)
	err = node.sendObserverTransaction(ctx, &common.Operation{
		Id:    id,
		Type:  OperationTypeConfirmCall,
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
				if !recipient.Equals(groupDepositEntry) {
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
			if transfer, ok := solanaApp.DecodeTokenTransfer(accounts, ix.Data); ok {
				recipient := transfer.GetDestinationAccount().PublicKey
				token := transfer.GetMintAccount().PublicKey
				ata, _, err := solana.FindAssociatedTokenAddress(groupDepositEntry, token)
				if err != nil {
					return err
				}
				if !recipient.Equals(ata) {
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

func (node *Node) solanaClient() *solanaApp.Client {
	return solanaApp.NewClient(node.conf.SolanaRPC, node.conf.SolanaWsRPC)
}

func (node *Node) solanaAccount() solana.PublicKey {
	return solana.MustPrivateKeyFromBase58(node.conf.SolanaKey).PublicKey()
}
