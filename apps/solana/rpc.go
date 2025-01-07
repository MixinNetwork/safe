package solana

import (
	"context"
	"errors"
	"fmt"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	lookup "github.com/gagliardetto/solana-go/programs/address-lookup-table"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/ws"
)

func NewClient(rpcEndpoint, wsEndpoint string) *Client {
	return &Client{
		rpcEndpoint: rpcEndpoint,
		wsEndpoint:  wsEndpoint,
	}
}

type Client struct {
	rpcEndpoint string
	wsEndpoint  string

	rpcClient *rpc.Client
}

func (c *Client) getRPCClient() *rpc.Client {
	if c.rpcClient == nil {
		c.rpcClient = rpc.New(c.rpcEndpoint)
	}
	return c.rpcClient
}

func (c *Client) GetRPCClient() *rpc.Client {
	if c.rpcClient == nil {
		c.rpcClient = rpc.New(c.rpcEndpoint)
	}
	return c.rpcClient
}

func (c *Client) RPCGetBlockHeight(ctx context.Context) (int64, solana.Hash, error) {
	client := c.getRPCClient()
	result, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return 0, solana.Hash{}, err
	}

	return int64(result.Value.LastValidBlockHeight), result.Value.Blockhash, nil
}

func (c *Client) GetLatestBlockhash(ctx context.Context) (*rpc.GetLatestBlockhashResult, error) {
	client := c.getRPCClient()
	blockhash, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return nil, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}
	return blockhash, err
}

func (c *Client) connectWs(ctx context.Context) (*ws.Client, error) {
	return ws.Connect(ctx, c.wsEndpoint)
}

func (c *Client) RPCGetBlock(ctx context.Context, slot uint64) (*rpc.GetBlockResult, error) {
	client := c.getRPCClient()
	block, err := client.GetBlockWithOpts(ctx, slot, &rpc.GetBlockOpts{
		Encoding:                       solana.EncodingBase64,
		Commitment:                     rpc.CommitmentFinalized,
		MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
	})
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (c *Client) RPCGetBlockByHeight(ctx context.Context, height uint64) (*rpc.GetBlockResult, error) {
	client := c.getRPCClient()
	block, err := client.GetBlockWithOpts(ctx, height, &rpc.GetBlockOpts{
		Encoding:                       solana.EncodingBase64,
		Commitment:                     rpc.CommitmentFinalized,
		MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
		TransactionDetails:             rpc.TransactionDetailsFull,
	})
	if err != nil {
		if errors.Is(err, rpc.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return block, nil
}

func (c *Client) RPCGetAccount(ctx context.Context, account solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	result, err := c.GetRPCClient().GetAccountInfo(ctx, account)
	if err != nil {
		if err.Error() == "not found" {
			return nil, nil
		}
		return nil, fmt.Errorf("solana.GetAccountInfo() => %v", err)
	}
	return result, nil
}

func (c *Client) RPCGetTransaction(ctx context.Context, signature string) (*rpc.GetTransactionResult, error) {
	client := c.getRPCClient()
	r, err := client.GetTransaction(
		ctx,
		solana.MustSignatureFromBase58(signature),
		&rpc.GetTransactionOpts{
			Encoding:                       solana.EncodingBase58,
			MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
			Commitment:                     rpc.CommitmentFinalized,
		})
	if err != nil {
		return nil, err
	}

	if r.Meta == nil {
		return nil, fmt.Errorf("meta is nil")
	}

	return r, nil
}

func (c *Client) RPCGetTokenAccountsByOwner(ctx context.Context, owner solana.PublicKey) ([]token.Account, error) {
	client := c.getRPCClient()
	r, err := client.GetTokenAccountsByOwner(ctx, owner, &rpc.GetTokenAccountsConfig{
		ProgramId: &token.ProgramID,
	}, nil)
	if err != nil {
		return nil, err
	}

	var as []token.Account
	for _, account := range r.Value {
		var balance token.Account
		if err := bin.NewBinDecoder(account.Account.Data.GetBinary()).Decode(&balance); err != nil {
			return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
		}
		as = append(as, balance)
	}
	return as, nil
}

// processTransactionWithAddressLookups resolves the address lookups in the transaction.
func (c *Client) processTransactionWithAddressLookups(ctx context.Context, txx *solana.Transaction) error {
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

	rpcClient := c.getRPCClient()

	resolutions := make(map[solana.PublicKey]solana.PublicKeySlice)
	for _, key := range tblKeys {
		info, err := rpcClient.GetAccountInfo(ctx, key)
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

func (c *Client) GetNonceAccountHash(ctx context.Context, nonce solana.PublicKey) (*solana.Hash, error) {
	account, err := c.RPCGetAccount(ctx, nonce)
	if err != nil {
		return nil, fmt.Errorf("solana.GetAccountInfo() => %v", err)
	}
	if account == nil {
		return nil, nil
	}
	var nonceAccountData system.NonceAccount
	if err := bin.NewBinDecoder(account.Value.Data.GetBinary()).Decode(&nonceAccountData); err != nil {
		return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
	}
	hash := (solana.Hash)(nonceAccountData.Nonce)
	return &hash, nil
}

func (c *Client) GetMint(ctx context.Context, mint solana.PublicKey) (*token.Mint, error) {
	account, err := c.RPCGetAccount(ctx, mint)
	if err != nil {
		return nil, fmt.Errorf("solana.GetMint() => %v", err)
	}
	if account == nil {
		return nil, nil
	}
	var token token.Mint
	if err := bin.NewBinDecoder(account.Value.Data.GetBinary()).Decode(&token); err != nil {
		return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
	}
	return &token, nil
}
