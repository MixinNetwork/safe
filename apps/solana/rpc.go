package solana

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/mtg"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	lookup "github.com/gagliardetto/solana-go/programs/address-lookup-table"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

func NewClient(rpcEndpoint string) *Client {
	return &Client{
		rpcEndpoint: rpcEndpoint,
	}
}

type Client struct {
	rpcEndpoint string

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

func (c *Client) GetRPCClient() *rpc.Client {
	if c.rpcClient == nil {
		c.rpcClient = rpc.New(c.rpcEndpoint)
	}
	return c.rpcClient
}

func (c *Client) RPCGetBlockHeight(ctx context.Context) (uint64, error) {
	client := c.GetRPCClient()
	block, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return 0, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
	}
	return block.Context.Slot, nil
}

func (c *Client) RPCGetBlockByHeight(ctx context.Context, height uint64) (*rpc.GetBlockResult, error) {
	client := c.GetRPCClient()
	block, err := client.GetBlockWithOpts(ctx, height, &rpc.GetBlockOpts{
		Encoding:                       solana.EncodingBase64,
		Commitment:                     rpc.CommitmentConfirmed,
		MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
		TransactionDetails:             rpc.TransactionDetailsFull,
	})
	if err != nil && !errors.Is(err, rpc.ErrNotFound) {
		return nil, err
	}
	return block, nil
}

func (c *Client) getAssetMetadata(ctx context.Context, address string) (*AssetMetadata, error) {
	var resp struct {
		Content struct {
			Metadata AssetMetadata `json:"metadata"`
		} `json:"content"`
	}
	opt := map[string]any{
		"id": address,
	}
	err := c.GetRPCClient().RPCCallForInto(ctx, &resp, "getAsset", []any{opt})
	if err != nil {
		return nil, err
	}
	return &resp.Content.Metadata, nil
}

func (c *Client) RPCGetAsset(ctx context.Context, address string) (*Asset, error) {
	var mint token.Mint
	err := c.GetRPCClient().GetAccountDataInto(ctx, solana.MPK(address), &mint)
	if err != nil {
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

func (c *Client) RPCGetBalance(ctx context.Context, account solana.PublicKey) (uint64, error) {
	result, err := c.GetRPCClient().GetBalance(ctx, account, rpc.CommitmentConfirmed)
	if err != nil {
		return 0, fmt.Errorf("solana.GetAccountInfo(%s) => %v", account, err)
	}
	return result.Value, nil
}

func (c *Client) RPCGetAccount(ctx context.Context, account solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	result, err := c.GetRPCClient().GetAccountInfo(ctx, account)
	if err != nil && !errors.Is(err, rpc.ErrNotFound) {
		return nil, fmt.Errorf("solana.GetAccountInfo(%s) => %v", account, err)
	}
	return result, nil
}

func (c *Client) ReadAccountUntilSufficient(ctx context.Context, address solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	for {
		acc, err := c.RPCGetAccount(ctx, address)
		if mtg.CheckRetryableError(err) {
			time.Sleep(3 * time.Second)
			continue
		}
		if err != nil {
			return nil, err
		}
		if acc == nil {
			time.Sleep(3 * time.Second)
			continue
		}
		return acc, err
	}
}

func (c *Client) RPCGetTransaction(ctx context.Context, signature string, finalized bool) (*rpc.GetTransactionResult, error) {
	commitment := rpc.CommitmentConfirmed
	if finalized {
		commitment = rpc.CommitmentFinalized
	}

	r, err := c.GetRPCClient().GetTransaction(ctx,
		solana.MustSignatureFromBase58(signature),
		&rpc.GetTransactionOpts{
			Encoding:                       solana.EncodingBase58,
			MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
			Commitment:                     commitment,
		},
	)
	if err != nil || r.Meta == nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, fmt.Errorf("solana.GetTransaction(%s) => %v", signature, err)
	}

	return r, nil
}

func (c *Client) RPCGetTokenAccountsByOwner(ctx context.Context, owner solana.PublicKey) ([]*token.Account, error) {
	r, err := c.GetRPCClient().GetTokenAccountsByOwner(ctx, owner, &rpc.GetTokenAccountsConfig{
		ProgramId: &token.ProgramID,
	}, nil)
	if err != nil {
		return nil, err
	}

	as := make([]*token.Account, len(r.Value))
	for i, account := range r.Value {
		var a token.Account
		err := bin.NewBinDecoder(account.Account.Data.GetBinary()).Decode(&a)
		if err != nil {
			return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
		}
		as[i] = &a
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
	err = bin.NewBinDecoder(account.Value.Data.GetBinary()).Decode(&nonceAccountData)
	if err != nil {
		return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
	}
	hash := solana.Hash(nonceAccountData.Nonce)
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
	err = bin.NewBinDecoder(account.Value.Data.GetBinary()).Decode(&token)
	if err != nil {
		return nil, fmt.Errorf("solana.NewBinDecoder() => %v", err)
	}
	return &token, nil
}

func (c *Client) SendTransaction(ctx context.Context, tx *solana.Transaction) (string, error) {
	client := c.GetRPCClient()
	sig, err := client.SendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}
	return sig.String(), nil
}

// processTransactionWithAddressLookups resolves the address lookups in the transaction.
func (c *Client) ProcessTransactionWithAddressLookups(ctx context.Context, txx *solana.Transaction) error {
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

	rpcClient := c.GetRPCClient()

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
