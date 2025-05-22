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
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
)

func NewClient(rpcEndpoint string) *Client {
	return &Client{
		rpcEndpoint: rpcEndpoint,
		rpcClient:   rpc.New(rpcEndpoint),
	}
}

type Client struct {
	rpcClient   *rpc.Client
	rpcEndpoint string
}

type AssetMetadata struct {
	Symbol      string `json:"symbol"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Asset struct {
	Address  string `json:"address"`
	Id       string `json:"id"`
	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Decimals uint32 `json:"decimals"`
}

func (c *Client) RPCGetConfirmedHeight(ctx context.Context) (uint64, error) {
	for {
		block, err := c.rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("solana.GetLatestBlockhash() => %v", err)
		}
		return block.Context.Slot, nil
	}
}

func (c *Client) RPCGetBlockByHeight(ctx context.Context, height uint64) (*rpc.GetBlockResult, error) {
	for {
		block, err := c.rpcClient.GetBlockWithOpts(ctx, height, &rpc.GetBlockOpts{
			Encoding:                       solana.EncodingBase64,
			Commitment:                     rpc.CommitmentProcessed,
			MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
			TransactionDetails:             rpc.TransactionDetailsFull,
		})
		if mtg.CheckRetryableError(err) || errors.Is(err, rpc.ErrNotFound) {
			time.Sleep(1 * time.Second)
			continue
		}
		if err != nil {
			return nil, err
		}
		return block, nil
	}
}

func (c *Client) getAssetMetadata(ctx context.Context, address string) (*AssetMetadata, error) {
	for {
		var resp struct {
			Content struct {
				Metadata AssetMetadata `json:"metadata"`
			} `json:"content"`
		}
		err := c.rpcClient.RPCCallForInto(ctx, &resp, "getAsset", []any{address})
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		if err != nil {
			return nil, err
		}
		return &resp.Content.Metadata, nil
	}
}

func (c *Client) RPCGetAsset(ctx context.Context, address string) (*Asset, error) {
	var mint token.Mint
	for {
		err := c.rpcClient.GetAccountDataInto(ctx, solana.MPK(address), &mint)
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
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
}

func (c *Client) RPCGetBalance(ctx context.Context, account solana.PublicKey) (uint64, error) {
	for {
		result, err := c.rpcClient.GetBalance(ctx, account, rpc.CommitmentProcessed)
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("solana.GetAccountInfo(%s) => %v", account, err)
		}
		return result.Value, nil
	}
}

func (c *Client) RPCGetAccount(ctx context.Context, account solana.PublicKey) (*rpc.GetAccountInfoResult, error) {
	for {
		result, err := c.rpcClient.GetAccountInfoWithOpts(ctx, account, &rpc.GetAccountInfoOpts{
			Commitment: rpc.CommitmentProcessed,
		})
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		if err != nil && !errors.Is(err, rpc.ErrNotFound) {
			return nil, fmt.Errorf("solana.GetAccountInfo(%s) => %v", account, err)
		}
		return result, nil
	}
}

func (c *Client) RPCGetMultipleAccounts(ctx context.Context, accounts solana.PublicKeySlice) (*rpc.GetMultipleAccountsResult, error) {
	for {
		as, err := c.rpcClient.GetMultipleAccountsWithOpts(ctx, accounts, &rpc.GetMultipleAccountsOpts{
			Commitment: rpc.CommitmentProcessed,
		})
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		return as, err
	}
}

func (c *Client) RPCGetTransaction(ctx context.Context, signature string) (*rpc.GetTransactionResult, error) {
	for {
		r, err := c.rpcClient.GetTransaction(ctx,
			solana.MustSignatureFromBase58(signature),
			&rpc.GetTransactionOpts{
				Encoding:                       solana.EncodingBase58,
				MaxSupportedTransactionVersion: &rpc.MaxSupportedTransactionVersion1,
				Commitment:                     rpc.CommitmentConfirmed, // getTransaction requires this min level
			},
		)
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		if err != nil || r.Meta == nil {
			if strings.Contains(err.Error(), "not found") {
				return nil, nil
			}
			return nil, fmt.Errorf("solana.GetTransaction(%s) => %v", signature, err)
		}

		return r, nil
	}
}

func (c *Client) RPCGetMinimumBalanceForRentExemption(ctx context.Context, dataSize uint64) (uint64, error) {
	for {
		r, err := c.rpcClient.GetMinimumBalanceForRentExemption(ctx, dataSize, rpc.CommitmentProcessed)
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
		return r, err
	}
}

func (c *Client) RPCGetTokenAccountsByOwner(ctx context.Context, owner solana.PublicKey) ([]*token.Account, error) {
	for {
		r, err := c.rpcClient.GetTokenAccountsByOwner(ctx, owner, &rpc.GetTokenAccountsConfig{
			ProgramId: &token.ProgramID,
		}, nil)
		if mtg.CheckRetryableError(err) {
			time.Sleep(1 * time.Second)
			continue
		}
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
	sig, err := c.rpcClient.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentProcessed,
	})
	if err != nil {
		return "", err
	}
	return sig.String(), nil
}
