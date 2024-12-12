package solana

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/solana/squads_mpl"
	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gofrs/uuid"
)

const (
	ChainSolana = 7

	SolanaMixinChainId         = "64692c23-8971-4cf4-84a7-4dd1271dd887"
	SolanaEmptyAddress         = "11111111111111111111111111111111"
	NativeTokenDecimals uint32 = 9
)

func init() {
	programID := solana.MustPublicKeyFromBase58("SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu")
	squads_mpl.SetProgramID(programID)
}

type Asset struct {
	Address  string
	Id       string
	Symbol   string
	Name     string
	Decimals uint32
}

type Transfer struct {
	// Signature is the signature of the transaction that contains the transfer.
	Signature string

	// Index is the index of the transfer in the transaction.
	Index int64

	// TokenAddress is the address of the token that is being transferred.
	// If the token is SPL Token, it will be the address of the mint.
	// If the token is native SOL, it will be 'SolanaMintAddress'.
	TokenAddress string

	// AssetId is the mixin version asset id
	AssetId string

	Sender   string
	Receiver string
	Value    *big.Int
}

func CheckFinalization(num uint64) bool {
	return num >= 32
}

// GenerateAssetId generates a mixin version asset id from a Solana token address.
func GenerateAssetId(assetKey string) string {
	_ = solana.MustPublicKeyFromBase58(assetKey)
	return buildChainAssetId(SolanaMixinChainId, assetKey)
}

func buildChainAssetId(base, asset string) string {
	h := md5.New()
	_, _ = io.WriteString(h, base)
	_, _ = io.WriteString(h, asset)
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x30
	sum[8] = (sum[8] & 0x3f) | 0x80
	id, err := uuid.FromBytes(sum)
	if err != nil {
		panic(hex.EncodeToString(sum))
	}
	return id.String()
}

func (c *Client) VerifyDeposit(ctx context.Context, hash, assetAddress, destination string, index int64, amount *big.Int) (*Transfer, *rpc.GetTransactionResult, error) {
	etx, err := c.RPCGetTransaction(ctx, hash)
	logger.Printf("solana.RPCGetTransaction(%s) => %v %v", hash, etx, err)
	if err != nil {
		return nil, nil, fmt.Errorf("malicious solana deposit or node not in sync? %s %v", hash, err)
	}

	transfers, err := c.ExtractTransfersFromTransaction(ctx, etx)
	logger.Printf("solana.ExtractTransfersFromTransaction(%s) => %v %v", hash, transfers, err)
	if err != nil {
		return nil, nil, err
	}

	for _, transfer := range transfers {
		if transfer.TokenAddress == assetAddress && transfer.Index == index && transfer.Receiver == destination && amount.Cmp(transfer.Value) == 0 {
			return transfer, etx, nil
		}
	}

	return nil, nil, nil
}

func (c *Client) ExtractTransfersFromTransaction(ctx context.Context, result *rpc.GetTransactionResult) ([]*Transfer, error) {
	meta := result.Meta
	if meta == nil {
		return nil, fmt.Errorf("meta is nil")
	}

	if meta.Err != nil {
		// Transaction failed, ignore
		return nil, nil
	}

	tx, err := result.Transaction.GetTransaction()
	if err != nil {
		return nil, err
	}

	hash := tx.Signatures[0].String()
	if err := c.processTransactionWithAddressLookups(ctx, tx); err != nil {
		return nil, err
	}

	msg := tx.Message

	var (
		transfers         = []*Transfer{}
		innerInstructions = map[uint16][]solana.CompiledInstruction{}
		tokenAccounts     = map[solana.PublicKey]token.Account{}
	)

	for _, inner := range meta.InnerInstructions {
		innerInstructions[inner.Index] = inner.Instructions
	}

	for _, balance := range meta.PreTokenBalances {
		if account, err := msg.Account(balance.AccountIndex); err == nil {
			tokenAccounts[account] = token.Account{
				Owner: *balance.Owner,
				Mint:  balance.Mint,
			}
		}
	}

	for index, ix := range msg.Instructions {
		baseIndex := int64(index+1) * 10000
		if transfer := extractTransfersFromInstruction(&msg, ix, tokenAccounts); transfer != nil {
			transfer.Signature = hash
			transfer.Index = baseIndex
			transfers = append(transfers, transfer)
		}

		for innerIndex, inner := range innerInstructions[uint16(index)] {
			if transfer := extractTransfersFromInstruction(&msg, inner, tokenAccounts); transfer != nil {
				transfer.Signature = hash
				transfer.Index = baseIndex + int64(innerIndex) + 1
				transfers = append(transfers, transfer)
			}
		}
	}

	return transfers, nil
}

func extractTransfersFromInstruction(msg *solana.Message, cix solana.CompiledInstruction, tokenAccounts map[solana.PublicKey]token.Account) *Transfer {
	programKey, err := msg.Program(cix.ProgramIDIndex)
	if err != nil {
		panic(err)
	}

	accounts, err := cix.ResolveInstructionAccounts(msg)
	if err != nil {
		panic(err)
	}

	switch programKey {
	case system.ProgramID:
		if transfer, ok := decodeSystemTransfer(accounts, cix.Data); ok {
			return &Transfer{
				TokenAddress: SolanaEmptyAddress,
				AssetId:      SolanaMixinChainId,
				Sender:       transfer.GetFundingAccount().PublicKey.String(),
				Receiver:     transfer.GetRecipientAccount().PublicKey.String(),
				Value:        new(big.Int).SetUint64(*transfer.Lamports),
			}
		}
	case solana.TokenProgramID, solana.Token2022ProgramID:
		if transfer, ok := decodeTokenTransfer(accounts, cix.Data); ok {
			from, ok := tokenAccounts[transfer.GetSourceAccount().PublicKey]
			if !ok {
				panic(fmt.Sprintf("token account not found: %s", transfer.GetSourceAccount().PublicKey.String()))
			}

			to, ok := tokenAccounts[transfer.GetDestinationAccount().PublicKey]
			if !ok {
				panic(fmt.Sprintf("token account not found: %s", transfer.GetDestinationAccount().PublicKey.String()))
			}

			return &Transfer{
				TokenAddress: from.Mint.String(),
				AssetId:      buildChainAssetId(SolanaMixinChainId, from.Mint.String()),
				Sender:       from.Owner.String(),
				Receiver:     to.Owner.String(),
				Value:        new(big.Int).SetUint64(*transfer.Amount),
			}
		}
	}

	return nil
}

func decodeSystemTransfer(accounts solana.AccountMetaSlice, data []byte) (*system.Transfer, bool) {
	ix, err := system.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if transfer, ok := ix.Impl.(*system.Transfer); ok {
		return transfer, true
	}

	if transferWithSeed, ok := ix.Impl.(*system.TransferWithSeed); ok {
		t := system.NewTransferInstructionBuilder()
		t.SetFundingAccount(transferWithSeed.GetFundingAccount().PublicKey)
		t.SetRecipientAccount(transferWithSeed.GetRecipientAccount().PublicKey)
		t.SetLamports(*transferWithSeed.Lamports)
		return t, true
	}

	return nil, false
}

func decodeTokenTransfer(accounts solana.AccountMetaSlice, data []byte) (*token.Transfer, bool) {
	ix, err := token.DecodeInstruction(accounts, data)
	if err != nil {
		return nil, false
	}

	if transfer, ok := ix.Impl.(*token.Transfer); ok {
		return transfer, true
	}

	if transferChecked, ok := ix.Impl.(*token.TransferChecked); ok {
		t := token.NewTransferInstructionBuilder()
		t.SetSourceAccount(transferChecked.GetSourceAccount().PublicKey)
		t.SetDestinationAccount(transferChecked.GetDestinationAccount().PublicKey)
		t.SetAmount(*transferChecked.Amount)
		return t, true
	}

	return nil, false
}
