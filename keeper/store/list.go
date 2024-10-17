package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/shopspring/decimal"
)

func (s *SQLite3Store) ImportBackup(ctx context.Context, bd *SQLite3Store) error {
	logger.Println("Reading data from backup database...")

	requests, err := bd.listRequests(ctx)
	if err != nil {
		return err
	}
	infos, err := bd.listLatestNetworkInfos(ctx)
	if err != nil {
		return err
	}
	ops, err := bd.listLatestOperationParams(ctx)
	if err != nil {
		return err
	}
	assets, err := bd.listAssets(ctx)
	if err != nil {
		return err
	}
	keys, err := bd.listKeys(ctx)
	if err != nil {
		return err
	}
	proposals, err := bd.listProposals(ctx)
	if err != nil {
		return err
	}
	safes, err := bd.listSafes(ctx)
	if err != nil {
		return err
	}
	outputs, err := bd.listBitcoinOutputs(ctx)
	if err != nil {
		return err
	}
	balances, err := bd.listEthereumBalances(ctx)
	if err != nil {
		return err
	}
	deposits, err := bd.listDeposits(ctx)
	if err != nil {
		return err
	}
	txs, err := bd.listTransactions(ctx)
	if err != nil {
		return err
	}
	signatures, err := bd.listSignatureRequests(ctx)
	if err != nil {
		return err
	}
	properties, err := bd.listProperties(ctx)
	if err != nil {
		return err
	}

	return s.Export(ctx, ExportData{
		Requests:          requests,
		NetworkInfos:      infos,
		OperationParams:   ops,
		Assets:            assets,
		Keys:              keys,
		SafeProposals:     proposals,
		Safes:             safes,
		BitcoinOutputs:    outputs,
		EthereumBalances:  balances,
		Deposits:          deposits,
		Transactions:      txs,
		SignatureRequests: signatures,
		Properties:        properties,
	})
}

func (s *SQLite3Store) listRequests(ctx context.Context) ([]*common.Request, error) {
	var cols = []string{"request_id", "mixin_hash", "mixin_index", "asset_id", "amount", "role", "action", "curve", "holder", "extra", "state", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM requests ORDER BY created_at ASC, request_id ASC", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []*common.Request
	for rows.Next() {
		var mh string
		var r common.Request
		err = rows.Scan(&r.Id, &mh, &r.MixinIndex, &r.AssetId, &r.Amount, &r.Role, &r.Action, &r.Curve, &r.Holder, &r.ExtraHEX, &r.State, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		r.MixinHash, err = crypto.HashFromString(mh)
		if err != nil {
			return nil, err
		}
		requests = append(requests, &r)
	}
	return requests, nil
}

func (s *SQLite3Store) readLatestNetworkInfo(ctx context.Context, chain int64) (*NetworkInfo, error) {
	var cols = []string{"request_id", "chain", "fee", "height", "hash", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM network_infos WHERE chain=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(cols, ","))
	row := s.db.QueryRowContext(ctx, query, chain)

	var n NetworkInfo
	err := row.Scan(&n.RequestId, &n.Chain, &n.Fee, &n.Height, &n.Hash, &n.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &n, err
}

func (s *SQLite3Store) listLatestNetworkInfos(ctx context.Context) ([]*NetworkInfo, error) {
	var infos []*NetworkInfo
	for _, c := range []int64{common.SafeChainBitcoin, common.SafeChainEthereum, common.SafeChainLitecoin, common.SafeChainPolygon} {
		info, err := s.readLatestNetworkInfo(ctx, c)
		if err != nil || info == nil {
			return nil, fmt.Errorf("legacy.readLatestNetworkInfo(%d) => %v %v", c, info, err)
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *SQLite3Store) readLatestOperationParams(ctx context.Context, chain int64) (*OperationParams, error) {
	var cols = []string{"request_id", "chain", "price_asset", "price_amount", "transaction_minimum", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM operation_params WHERE chain=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(cols, ","))
	row := s.db.QueryRowContext(ctx, query, chain)

	var p OperationParams
	var price, minimum string
	err := row.Scan(&p.RequestId, &p.Chain, &p.OperationPriceAsset, &price, &minimum, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	p.OperationPriceAmount = decimal.RequireFromString(price)
	p.TransactionMinimum = decimal.RequireFromString(minimum)
	return &p, nil
}

func (s *SQLite3Store) listLatestOperationParams(ctx context.Context) ([]*OperationParams, error) {
	var ops []*OperationParams
	for _, c := range []int64{common.SafeChainBitcoin, common.SafeChainEthereum, common.SafeChainLitecoin, common.SafeChainPolygon} {
		op, err := s.readLatestOperationParams(ctx, c)
		if err != nil || op == nil {
			return nil, fmt.Errorf("legacy.readLatestOperationParams(%d) => %v %v", c, op, err)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

func (s *SQLite3Store) listAssets(ctx context.Context) ([]*Asset, error) {
	var cols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM assets", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*Asset
	for rows.Next() {
		var a Asset
		err := rows.Scan(&a.AssetId, &a.MixinId, &a.AssetKey, &a.Symbol, &a.Name, &a.Decimals, &a.Chain, &a.CreatedAt)
		if err != nil {
			return nil, err
		}
		assets = append(assets, &a)
	}
	return assets, nil
}

func (s *SQLite3Store) listKeys(ctx context.Context) ([]*Key, error) {
	var cols = []string{"public_key", "curve", "request_id", "role", "extra", "flags", "holder", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM keys", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		var k Key
		err := rows.Scan(&k.Public, &k.Curve, &k.RequestId, &k.Role, &k.Extra, &k.Flags, &k.Holder, &k.CreatedAt, &k.UpdatedAt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}

func (s *SQLite3Store) listProposals(ctx context.Context) ([]*SafeProposal, error) {
	var cols = []string{"request_id", "chain", "holder", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM safe_proposals", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ps []*SafeProposal
	for rows.Next() {
		var s SafeProposal
		var receivers string
		err := rows.Scan(&s.RequestId, &s.Chain, &s.Holder, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		s.Receivers = strings.Split(receivers, ";")
		ps = append(ps, &s)
	}
	return ps, nil
}

func (s *SQLite3Store) listSafes(ctx context.Context) ([]*Safe, error) {
	var cols = []string{"holder", "chain", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "request_id", "nonce", "state", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM safes", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var safes []*Safe
	for rows.Next() {
		var s Safe
		var receivers string
		err := rows.Scan(&s.Holder, &s.Chain, &s.Signer, &s.Observer, &s.Timelock, &s.Path, &s.Address, &s.Extra, &receivers, &s.Threshold, &s.RequestId, &s.Nonce, &s.State, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		s.Receivers = strings.Split(receivers, ";")
		safes = append(safes, &s)
	}
	return safes, nil
}

func (s *SQLite3Store) listBitcoinOutputs(ctx context.Context) ([]*BitcoinOutput, error) {
	cols := strings.Join([]string{"transaction_hash", "output_index", "address", "satoshi", "script", "sequence", "chain", "state", "spent_by", "request_id", "created_at", "updated_at"}, ",")
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs ORDER BY created_at ASC, request_id ASC", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inputs []*BitcoinOutput
	for rows.Next() {
		var script string
		var input BitcoinOutput
		err = rows.Scan(&input.TransactionHash, &input.Index, &input.Address, &input.Satoshi, &script, &input.Sequence, &input.Chain, &input.State, &input.SpentBy, &input.RequestId, &input.CreatedAt, &input.UpdatedAt)
		if err != nil {
			return nil, err
		}
		b, _ := hex.DecodeString(script)
		input.Script = b
		inputs = append(inputs, &input)
	}
	return inputs, nil
}

func (s *SQLite3Store) listEthereumBalances(ctx context.Context) ([]*SafeBalance, error) {
	cols := []string{"address", "asset_id", "asset_address", "balance", "latest_tx_hash", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM ethereum_balances", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sbs []*SafeBalance
	for rows.Next() {
		b, err := BalancFromRow(rows)
		if err != nil {
			return nil, err
		}
		sbs = append(sbs, b)
	}
	return sbs, nil
}

func (s *SQLite3Store) listDeposits(ctx context.Context) ([]*Deposit, error) {
	var cols = []string{"transaction_hash", "output_index", "asset_id", "amount", "receiver", "sender", "state", "chain", "holder", "category", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM deposits", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ds []*Deposit
	for rows.Next() {
		var d Deposit
		err = rows.Scan(&d.TransactionHash, &d.OutputIndex, &d.AssetId, &d.Amount, &d.Receiver, &d.Sender, &d.State, &d.Chain, &d.Holder, &d.Category, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}
		ds = append(ds, &d)
	}
	return ds, nil
}

func (s *SQLite3Store) listTransactions(ctx context.Context) ([]*Transaction, error) {
	var cols = []string{"transaction_hash", "raw_transaction", "holder", "chain", "asset_id", "state", "data", "request_id", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM transactions", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var txs []*Transaction
	for rows.Next() {
		var tx Transaction
		err = rows.Scan(&tx.TransactionHash, &tx.RawTransaction, &tx.Holder, &tx.Chain, &tx.AssetId, &tx.State, &tx.Data, &tx.RequestId, &tx.CreatedAt, &tx.UpdatedAt)
		if err != nil {
			return nil, err
		}
		txs = append(txs, &tx)
	}
	return txs, nil
}

func (s *SQLite3Store) listSignatureRequests(ctx context.Context) ([]*SignatureRequest, error) {
	var cols = []string{"request_id", "transaction_hash", "input_index", "signer", "curve", "message", "signature", "state", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM signature_requests ORDER BY created_at DESC, request_id DESC", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rs []*SignatureRequest
	for rows.Next() {
		var r SignatureRequest
		err := rows.Scan(&r.RequestId, &r.TransactionHash, &r.InputIndex, &r.Signer, &r.Curve, &r.Message, &r.Signature, &r.State, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		rs = append(rs, &r)
	}
	return rs, nil
}

func (s *SQLite3Store) listProperties(ctx context.Context) ([]*Property, error) {
	var cols = []string{"key", "value", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM properties", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ps []*Property
	for rows.Next() {
		var p Property
		err := rows.Scan(&p.Key, &p.Value, &p.CreatedAt)
		if err != nil {
			return nil, err
		}
		ps = append(ps, &p)
	}
	return ps, nil
}
