package legacy

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/shopspring/decimal"
)

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

func (s *SQLite3Store) readLatestNetworkInfo(ctx context.Context, chain int64) (*store.NetworkInfo, error) {
	var cols = []string{"request_id", "chain", "fee", "height", "hash", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM network_infos WHERE chain=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(cols, ","))
	row := s.db.QueryRowContext(ctx, query, chain)

	var n store.NetworkInfo
	err := row.Scan(&n.RequestId, &n.Chain, &n.Fee, &n.Height, &n.Hash, &n.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &n, err
}

func (s *SQLite3Store) listLatestNetworkInfos(ctx context.Context) ([]*store.NetworkInfo, error) {
	var infos []*store.NetworkInfo
	for _, c := range []int64{common.SafeChainBitcoin, common.SafeChainEthereum, common.SafeChainLitecoin, common.SafeChainPolygon} {
		info, err := s.readLatestNetworkInfo(ctx, c)
		if err != nil || info == nil {
			return nil, fmt.Errorf("legacy.readLatestNetworkInfo(%d) => %v %v", c, info, err)
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *SQLite3Store) readLatestOperationParams(ctx context.Context, chain int64) (*store.OperationParams, error) {
	var cols = []string{"request_id", "chain", "price_asset", "price_amount", "transaction_minimum", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM operation_params WHERE chain=? ORDER BY created_at DESC, request_id DESC LIMIT 1", strings.Join(cols, ","))
	row := s.db.QueryRowContext(ctx, query, chain)

	var p store.OperationParams
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

func (s *SQLite3Store) listLatestOperationParams(ctx context.Context) ([]*store.OperationParams, error) {
	var ops []*store.OperationParams
	for _, c := range []int64{common.SafeChainBitcoin, common.SafeChainEthereum, common.SafeChainLitecoin, common.SafeChainPolygon} {
		op, err := s.readLatestOperationParams(ctx, c)
		if err != nil || op == nil {
			return nil, fmt.Errorf("legacy.readLatestOperationParams(%d) => %v %v", c, op, err)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

func (s *SQLite3Store) listAssets(ctx context.Context) ([]*store.Asset, error) {
	var cols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM assets", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*store.Asset
	for rows.Next() {
		var a store.Asset
		err := rows.Scan(&a.AssetId, &a.MixinId, &a.AssetKey, &a.Symbol, &a.Name, &a.Decimals, &a.Chain, &a.CreatedAt)
		if err != nil {
			return nil, err
		}
		assets = append(assets, &a)
	}
	return assets, nil
}

func (s *SQLite3Store) listKeys(ctx context.Context) ([]*store.Key, error) {
	var cols = []string{"public_key", "curve", "request_id", "role", "extra", "flags", "holder", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM keys", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*store.Key
	for rows.Next() {
		var k store.Key
		err := rows.Scan(&k.Public, &k.Curve, &k.RequestId, &k.Role, &k.Extra, &k.Flags, &k.Holder, &k.CreatedAt, &k.UpdatedAt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &k)
	}
	return keys, nil
}

func (s *SQLite3Store) listProposals(ctx context.Context) ([]*store.SafeProposal, error) {
	var cols = []string{"request_id", "chain", "holder", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM safe_proposals", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ps []*store.SafeProposal
	for rows.Next() {
		var s store.SafeProposal
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

func (s *SQLite3Store) listSafes(ctx context.Context) ([]*store.Safe, error) {
	var cols = []string{"holder", "chain", "signer", "observer", "timelock", "path", "address", "extra", "receivers", "threshold", "request_id", "nonce", "state", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM safes", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var safes []*store.Safe
	for rows.Next() {
		var s store.Safe
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

func (s *SQLite3Store) listBitcoinOutputs(ctx context.Context) ([]*store.BitcoinOutput, error) {
	cols := strings.Join([]string{"transaction_hash", "output_index", "address", "satoshi", "script", "sequence", "chain", "state", "spent_by", "request_id", "created_at", "updated_at"}, ",")
	query := fmt.Sprintf("SELECT %s FROM bitcoin_outputs ORDER BY created_at ASC, request_id ASC", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inputs []*store.BitcoinOutput
	for rows.Next() {
		var script string
		var input store.BitcoinOutput
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

func (s *SQLite3Store) listEthereumBalances(ctx context.Context) ([]*store.SafeBalance, error) {
	cols := []string{"address", "asset_id", "asset_address", "balance", "latest_tx_hash", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM ethereum_balances", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sbs []*store.SafeBalance
	for rows.Next() {
		b, err := store.BalancFromRow(rows)
		if err != nil {
			return nil, err
		}
		sbs = append(sbs, b)
	}
	return sbs, nil
}

func (s *SQLite3Store) listDeposits(ctx context.Context) ([]*store.Deposit, error) {
	var cols = []string{"transaction_hash", "output_index", "asset_id", "amount", "receiver", "sender", "state", "chain", "holder", "category", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM deposits", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ds []*store.Deposit
	for rows.Next() {
		var d store.Deposit
		err = rows.Scan(&d.TransactionHash, &d.OutputIndex, &d.AssetId, &d.Amount, &d.Receiver, &d.Sender, &d.State, &d.Chain, &d.Holder, &d.Category, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}
		ds = append(ds, &d)
	}
	return ds, nil
}

func (s *SQLite3Store) listTransactions(ctx context.Context) ([]*store.Transaction, error) {
	var cols = []string{"transaction_hash", "raw_transaction", "holder", "chain", "asset_id", "state", "data", "request_id", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM transactions", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var txs []*store.Transaction
	for rows.Next() {
		var tx store.Transaction
		err = rows.Scan(&tx.TransactionHash, &tx.RawTransaction, &tx.Holder, &tx.Chain, &tx.AssetId, &tx.State, &tx.Data, &tx.RequestId, &tx.CreatedAt, &tx.UpdatedAt)
		if err != nil {
			return nil, err
		}
		txs = append(txs, &tx)
	}
	return txs, nil
}

func (s *SQLite3Store) listSignatureRequests(ctx context.Context) ([]*store.SignatureRequest, error) {
	var cols = []string{"request_id", "transaction_hash", "input_index", "signer", "curve", "message", "signature", "state", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM signature_requests ORDER BY created_at DESC, request_id DESC", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rs []*store.SignatureRequest
	for rows.Next() {
		var r store.SignatureRequest
		err := rows.Scan(&r.RequestId, &r.TransactionHash, &r.InputIndex, &r.Signer, &r.Curve, &r.Message, &r.Signature, &r.State, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		rs = append(rs, &r)
	}
	return rs, nil
}

func (s *SQLite3Store) listProperties(ctx context.Context) ([]*store.Property, error) {
	var cols = []string{"key", "value", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM properties", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ps []*store.Property
	for rows.Next() {
		var p store.Property
		err := rows.Scan(&p.Key, &p.Value, &p.CreatedAt)
		if err != nil {
			return nil, err
		}
		ps = append(ps, &p)
	}
	return ps, nil
}
