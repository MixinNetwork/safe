package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/safe/common"
)

type Property struct {
	Key       string
	Value     string
	CreatedAt time.Time
}

type BitcoinOutput struct {
	TransactionHash string
	Index           uint32
	Address         string
	Satoshi         int64
	Script          []byte
	Sequence        uint32
	Chain           int64
	State           int64
	SpentBy         sql.NullString
	RequestId       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type ExportData struct {
	Requests          []*common.Request
	NetworkInfos      []*NetworkInfo
	OperationParams   []*OperationParams
	Assets            []*Asset
	Keys              []*Key
	SafeProposals     []*SafeProposal
	Safes             []*Safe
	BitcoinOutputs    []*BitcoinOutput
	EthereumBalances  []*SafeBalance
	Deposits          []*Deposit
	Transactions      []*Transaction
	SignatureRequests []*SignatureRequest
	Properties        []*Property
}

func (s *SQLite3Store) Export(ctx context.Context, data ExportData) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	fmt.Println("Exporting requests...")
	err = s.exportRequests(ctx, tx, data.Requests)
	if err != nil {
		return err
	}
	fmt.Println("Exporting network_infos...")
	err = s.exportNetworkInfos(ctx, tx, data.NetworkInfos)
	if err != nil {
		return err
	}
	fmt.Println("Exporting operation_params...")
	err = s.exportOperationParams(ctx, tx, data.OperationParams)
	if err != nil {
		return err
	}
	fmt.Println("Exporting assets...")
	err = s.exportAssets(ctx, tx, data.Assets)
	if err != nil {
		return err
	}
	fmt.Println("Exporting keys...")
	err = s.exportKeys(ctx, tx, data.Keys)
	if err != nil {
		return err
	}
	fmt.Println("Exporting safe_proposals...")
	err = s.exportSafeProposals(ctx, tx, data.SafeProposals)
	if err != nil {
		return err
	}
	fmt.Println("Exporting safes...")
	err = s.exportSafes(ctx, tx, data.Safes)
	if err != nil {
		return err
	}
	fmt.Println("Exporting bitcoin_outputs...")
	err = s.exportBitcoinOutputs(ctx, tx, data.BitcoinOutputs)
	if err != nil {
		return err
	}
	fmt.Println("Exporting ethereum_balances...")
	err = s.exportEthereumBalances(ctx, tx, data.EthereumBalances)
	if err != nil {
		return err
	}
	fmt.Println("Exporting deposits...")
	err = s.exportDeposits(ctx, tx, data.Deposits)
	if err != nil {
		return err
	}
	fmt.Println("Exporting transactions...")
	err = s.exportTransactions(ctx, tx, data.Transactions)
	if err != nil {
		return err
	}
	fmt.Println("Exporting signature Requests...")
	err = s.exportSignatureRequests(ctx, tx, data.SignatureRequests)
	if err != nil {
		return err
	}
	fmt.Println("Exporting properties...")
	err = s.exportProperties(ctx, tx, data.Properties)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) exportRequests(ctx context.Context, tx *sql.Tx, requests []*common.Request) error {
	for _, req := range requests {
		vals := []any{req.Id, req.MixinHash.String(), req.MixinIndex, req.AssetId, req.Amount, req.Role, req.Action, req.Curve, req.Holder, req.ExtraHEX, req.State, req.CreatedAt, req.CreatedAt, req.Sequence}
		err := s.execOne(ctx, tx, buildInsertionSQL("requests", requestCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT requests %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportNetworkInfos(ctx context.Context, tx *sql.Tx, infos []*NetworkInfo) error {
	for _, info := range infos {
		vals := []any{info.RequestId, info.Chain, info.Fee, info.Height, info.Hash, info.CreatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("network_infos", infoCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT network_infos %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportOperationParams(ctx context.Context, tx *sql.Tx, ops []*OperationParams) error {
	for _, params := range ops {
		amount := params.OperationPriceAmount.String()
		minimum := params.TransactionMinimum.String()
		vals := []any{params.RequestId, params.Chain, params.OperationPriceAsset, amount, minimum, params.CreatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("operation_params", paramsCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT operation_params %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportAssets(ctx context.Context, tx *sql.Tx, assets []*Asset) error {
	for _, asset := range assets {
		vals := []any{asset.AssetId, asset.MixinId, asset.AssetKey, asset.Symbol, asset.Name, asset.Decimals, asset.Chain, asset.CreatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("assets", assetCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT assets %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportKeys(ctx context.Context, tx *sql.Tx, keys []*Key) error {
	for _, key := range keys {
		vals := []any{key.Public, key.Curve, key.RequestId, key.Role, key.Extra, key.Flags, key.Holder, key.CreatedAt, key.UpdatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("keys", keyCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT keys %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportSafeProposals(ctx context.Context, tx *sql.Tx, proposals []*SafeProposal) error {
	for _, sp := range proposals {
		err := s.execOne(ctx, tx, buildInsertionSQL("safe_proposals", safeProposalCols), sp.values()...)
		if err != nil {
			return fmt.Errorf("INSERT safe_proposals %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportSafes(ctx context.Context, tx *sql.Tx, safes []*Safe) error {
	for _, safe := range safes {
		err := s.execOne(ctx, tx, buildInsertionSQL("safes", safeCols), safe.values()...)
		if err != nil {
			return fmt.Errorf("INSERT safes %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportBitcoinOutputs(ctx context.Context, tx *sql.Tx, outputs []*BitcoinOutput) error {
	for _, utxo := range outputs {
		script := hex.EncodeToString(utxo.Script)
		cols := []string{"transaction_hash", "output_index", "address", "satoshi", "script", "sequence", "chain", "state", "spent_by", "request_id", "created_at", "updated_at"}
		vals := []any{utxo.TransactionHash, utxo.Index, utxo.Address, utxo.Satoshi, script, utxo.Sequence, utxo.Chain, utxo.State, utxo.SpentBy, utxo.RequestId, utxo.CreatedAt, utxo.CreatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("bitcoin_outputs", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT bitcoin_outputs %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportEthereumBalances(ctx context.Context, tx *sql.Tx, balances []*SafeBalance) error {
	for _, balance := range balances {
		cols := []string{"address", "asset_id", "asset_address", "safe_asset_id", "balance", "latest_tx_hash", "updated_at"}
		vals := []any{balance.Address, balance.AssetId, balance.AssetAddress, balance.SafeAssetId, balance.balance, balance.LatestTxHash, balance.UpdatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("ethereum_balances", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT ethereum_balances %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportDeposits(ctx context.Context, tx *sql.Tx, deposits []*Deposit) error {
	for _, deposit := range deposits {
		vals := []any{deposit.TransactionHash, deposit.OutputIndex, deposit.AssetId, deposit.Amount, deposit.Receiver, deposit.Sender, deposit.State, deposit.Chain, deposit.Holder, deposit.Category, deposit.CreatedAt, deposit.CreatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("deposits", depositsCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT deposits %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportTransactions(ctx context.Context, tx *sql.Tx, transactions []*Transaction) error {
	for _, trx := range transactions {
		vals := []any{trx.TransactionHash, trx.RawTransaction, trx.Holder, trx.Chain, trx.AssetId, trx.State, trx.Data, trx.RequestId, trx.CreatedAt, trx.UpdatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT transactions %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportSignatureRequests(ctx context.Context, tx *sql.Tx, signatures []*SignatureRequest) error {
	for _, r := range signatures {
		vals := []any{r.RequestId, r.TransactionHash, r.InputIndex, r.Signer, r.Curve, r.Message, r.Signature, r.State, r.CreatedAt, r.UpdatedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("signature_requests", signatureCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT signature_requests %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportProperties(ctx context.Context, tx *sql.Tx, properties []*Property) error {
	for _, p := range properties {
		cols := []string{"key", "value", "created_at"}
		err := s.execOne(ctx, tx, buildInsertionSQL("properties", cols), p.Key, p.Value, p.CreatedAt)
		if err != nil {
			return fmt.Errorf("INSERT properties %v", err)
		}
	}
	return nil
}
