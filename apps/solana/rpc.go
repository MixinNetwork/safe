package solana

import (
	"context"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	lookup "github.com/gagliardetto/solana-go/programs/address-lookup-table"
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

func (c *Client) RPCGetAsset(ctx context.Context, address string) (*Asset, error) {
	panic("not implemented")
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
