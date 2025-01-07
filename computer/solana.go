package computer

import (
	"context"
	"fmt"

	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
)

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

func (node *Node) VerifySubSystemCall(ctx context.Context, tx *solana.Transaction, groupDepositEntry, user solana.PublicKey) error {
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
		case solana.TokenProgramID, solana.Token2022ProgramID:
			if mint, ok := solanaApp.DecodeTokenMint(accounts, ix.Data); ok {
				to := mint.GetDestinationAccount().PublicKey
				if !to.Equals(user) {
					return fmt.Errorf("invalid mint to destination: %s", to.String())
				}
				continue
			}
			if transfer, ok := solanaApp.DecodeTokenTransfer(accounts, ix.Data); ok {
				recipient := transfer.GetDestinationAccount().PublicKey
				if !recipient.Equals(groupDepositEntry) {
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
