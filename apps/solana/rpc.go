package solana

import (
	"context"
	"errors"
	"fmt"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
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

type AssetMetadata struct {
	Symbol      string `json:"symbol"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Asset struct {
	Address  string
	Id       string
	Symbol   string
	Name     string
	Decimals uint32
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

func (c *Client) getAssetMetadata(ctx context.Context, address string) (*AssetMetadata, error) {
	client := c.getRPCClient()

	var resp struct {
		Content struct {
			Metadata AssetMetadata `json:"metadata"`
		} `json:"content"`
	}

	opt := map[string]any{
		"id": address,
	}

	if err := client.RPCCallForInto(ctx, &resp, "getAsset", []any{opt}); err != nil {
		return nil, err
	}

	return &resp.Content.Metadata, nil
}

func (c *Client) RPCGetAsset(ctx context.Context, address string) (*Asset, error) {
	client := c.getRPCClient()
	var mint token.Mint
	if err := client.GetAccountDataInto(ctx, solana.MPK(address), &mint); err != nil {
		return nil, err
	}

	metadata, err := c.getAssetMetadata(ctx, address)
	if err != nil {
		return nil, err
	}

	asset := &Asset{
		Address:  address,
		Id:       GenerateAssetId(address),
		Decimals: uint32(mint.Decimals),
		Symbol:   metadata.Symbol,
		Name:     metadata.Name,
	}

	return asset, nil
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

func (c *Client) SendTransaction(ctx context.Context, tx *solana.Transaction) (string, error) {
	client := c.getRPCClient()
	sig, err := client.SendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}
	return sig.String(), nil
}
