package solana

import (
	"context"
	"errors"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	lookup "github.com/gagliardetto/solana-go/programs/address-lookup-table"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/ws"
)

func NewClient(rpcEndpoint, wsEndpoint string) *Client {
	return &Client{
		rpcEndpoint: rpcEndpoint,
		rpcClient:   rpc.New(rpcEndpoint),
		wsEndpoint:  wsEndpoint,
	}
}

type Client struct {
	rpcEndpoint string
	wsEndpoint  string

	rpcClient *rpc.Client
}

func (c *Client) getRPCClient() *rpc.Client {
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

func (c *Client) RPCGetBlockHeight(ctx context.Context) (int64, solana.Hash, error) {
	client := c.getRPCClient()
	result, err := client.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return 0, solana.Hash{}, err
	}

	return int64(result.Value.LastValidBlockHeight), result.Value.Blockhash, nil
}

func (c *Client) RPCGetUnitPrice(ctx context.Context) (uint64, error) {
	client := c.getRPCClient()
	// 获取最近的费用数据
	fees, err := client.GetRecentPrioritizationFees(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("get recent prioritization fees: %w", err)
	}

	if len(fees) == 0 {
		// 如果没有最近的费用数据，返回默认的最小费用 (5000 lamports)
		return 5000, nil
	}

	// 找出最低的费用
	minFee := uint64(^uint(0)) // 设置为最大uint64值
	for _, fee := range fees {
		if fee.PrioritizationFee < minFee {
			minFee = fee.PrioritizationFee
		}
	}

	return minFee, nil
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

func (c *Client) SendTransaction(ctx context.Context, tx *solana.Transaction) (string, error) {
	client := c.getRPCClient()
	sig, err := client.SendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}
	return sig.String(), nil
}
