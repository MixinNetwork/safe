package observer

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/util"
	"github.com/btcsuite/btcd/btcec/v2"
)

type Account struct {
	Address    string
	CreatedAt  time.Time
	Signature  sql.NullString
	ApprovedAt sql.NullTime
	DeployedAt sql.NullTime
	MigratedAt sql.NullTime
}

type Asset struct {
	AssetId   string
	MixinId   string
	AssetKey  string
	Symbol    string
	Name      string
	IconURL   string
	PriceUSD  string
	Decimals  uint32
	Chain     byte
	CreatedAt time.Time
}

type Deposit struct {
	TransactionHash string
	OutputIndex     int64
	AssetId         string
	AssetAddress    string
	Amount          string
	Receiver        string
	Sender          string
	State           int
	Chain           byte
	Holder          string
	Category        byte
	RequestId       string
	IsChange        bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type PendingDeposit struct {
	TransactionHash string    `json:"transaction_hash"`
	OutputIndex     int64     `json:"output_index"`
	AssetId         string    `json:"asset_id"`
	AssetAddress    string    `json:"asset_address"`
	Amount          string    `json:"amount"`
	Receiver        string    `json:"receiver"`
	Sender          string    `json:"sender"`
	State           int       `json:"state"`
	Chain           byte      `json:"chain"`
	Holder          string    `json:"holder"`
	CreatedAt       time.Time `json:"created_at"`
}

type Transaction struct {
	TransactionHash string
	RawTransaction  string
	Chain           byte
	Holder          string
	Signer          string
	State           byte
	SpentHash       sql.NullString
	SpentRaw        sql.NullString
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Output struct {
	TransactionHash string
	Index           uint32
	Address         string
	Satoshi         int64
	Chain           byte
	State           byte
	SpentBy         sql.NullString
	RawTransaction  sql.NullString
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Recovery struct {
	Address         string
	Chain           byte
	Holder          string
	Observer        string
	RawTransaction  string
	TransactionHash string
	State           int
	IsInheritance   bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type NodeStats struct {
	AppId     string
	Type      string
	Stats     string
	UpdatedAt time.Time
}

type Cache struct {
	Key       string
	Value     string
	CreatedAt time.Time
}

const cacheTTL = 1 * time.Hour

var accountCols = []string{"address", "created_at", "signature", "approved_at", "deployed_at", "migrated_at"}

var assetCols = []string{"asset_id", "mixin_id", "asset_key", "symbol", "name", "decimals", "chain", "created_at"}

var depositsCols = []string{"transaction_hash", "output_index", "asset_id", "asset_address", "amount", "receiver", "sender", "state", "chain", "holder", "category", "request_id", "is_change", "created_at", "updated_at"}

var pendingDepositsCols = []string{"transaction_hash", "output_index", "asset_id", "asset_address", "amount", "receiver", "sender", "state", "chain", "holder", "created_at"}

func (d *Deposit) values() []any {
	return []any{d.TransactionHash, d.OutputIndex, d.AssetId, d.AssetAddress, d.Amount, d.Receiver, d.Sender, d.State, d.Chain, d.Holder, d.Category, d.RequestId, d.IsChange, d.CreatedAt, d.UpdatedAt}
}

func (d *PendingDeposit) values() []any {
	return []any{d.TransactionHash, d.OutputIndex, d.AssetId, d.AssetAddress, d.Amount, d.Receiver, d.Sender, d.State, d.Chain, d.Holder, d.CreatedAt}
}

var transactionCols = []string{"transaction_hash", "raw_transaction", "chain", "holder", "signer", "state", "spent_hash", "spent_raw", "created_at", "updated_at"}

func (t *Transaction) values() []any {
	return []any{t.TransactionHash, t.RawTransaction, t.Chain, t.Holder, t.Signer, t.State, t.SpentHash, t.SpentRaw, t.CreatedAt, t.UpdatedAt}
}

var outputCols = []string{"transaction_hash", "output_index", "address", "satoshi", "chain", "state", "spent_by", "raw_transaction", "created_at", "updated_at"}

func (o *Output) values() []any {
	return []any{o.TransactionHash, o.Index, o.Address, o.Satoshi, o.Chain, o.State, o.SpentBy, o.RawTransaction, o.CreatedAt, o.UpdatedAt}
}

var recoveryCols = []string{"address", "chain", "holder", "observer", "raw_transaction", "transaction_hash", "state", "inheritance", "created_at", "updated_at"}

func (r *Recovery) values() []any {
	return []any{r.Address, r.Chain, r.Holder, r.Observer, r.RawTransaction, r.TransactionHash, r.State, r.IsInheritance, r.CreatedAt, r.UpdatedAt}
}

var nodeCols = []string{"app_id", "node_type", "stats", "updated_at"}

func (n *NodeStats) values() []any {
	return []any{n.AppId, n.Type, n.Stats, n.UpdatedAt}
}

func (n *NodeStats) getStats() (*StatsInfo, error) {
	ns := &StatsInfo{}
	err := json.Unmarshal([]byte(n.Stats), ns)
	return ns, err
}

func (r *Recovery) getState() string {
	switch r.State {
	case common.RequestStateInitial:
		return "initial"
	case common.RequestStatePending:
		return "pending"
	case common.RequestStateDone:
		return "done"
	case common.RequestStateFailed:
		return "failed"
	}
	panic(r.State)
}

func (t *Transaction) Signers(ctx context.Context, node *Node, safe *store.Safe) []string {
	signers := make([]string, 0)
	if t.State == common.RequestStateFailed {
		return signers
	}

	opk, spk := safe.Observer, safe.Signer
	switch safe.Chain {
	case common.SafeChainBitcoin, common.SafeChainLitecoin:
		var err error
		opk, err = node.deriveBIP32WithKeeperPath(ctx, safe.Observer, safe.Path)
		if err != nil {
			panic(err)
		}
		spk, err = node.deriveBIP32WithKeeperPath(ctx, t.Signer, safe.Path)
		if err != nil {
			panic(err)
		}
	}

	pubs := []string{t.Holder, spk, opk}
	for idx, pub := range pubs {
		isSigned := false
		switch safe.Chain {
		case common.SafeChainBitcoin, common.SafeChainLitecoin:
			isSigned = bitcoin.CheckTransactionPartiallySignedBy(t.RawTransaction, pub)
		case common.SafeChainPolygon, common.SafeChainEthereum:
			isSigned = ethereum.CheckTransactionPartiallySignedBy(t.RawTransaction, pub)
		default:
			panic(safe.Chain)
		}
		if isSigned {
			switch idx {
			case 0:
				signers = append(signers, "holder")
			case 1:
				signers = append(signers, "signer")
			case 2:
				signers = append(signers, "observer")
			}
		}
	}

	return signers
}

func (s *SQLite3Store) WriteAccountProposalIfNotExists(ctx context.Context, address string, createdAt time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT created_at FROM accounts WHERE address=?", address)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("accounts", accountCols), address, createdAt, sql.NullString{}, sql.NullTime{}, sql.NullTime{}, createdAt)
	if err != nil {
		return fmt.Errorf("INSERT accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) CheckAccountProposed(ctx context.Context, addr string) (bool, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT created_at FROM accounts WHERE address=?", addr)
	if err != nil {
		return false, err
	}
	defer util.CloseOrPanic(rows)

	return rows.Next(), nil
}

func (s *SQLite3Store) ReadAccount(ctx context.Context, addr string) (*Account, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer common.Rollback(tx)

	return s.readAccount(ctx, tx, addr)
}

func (s *SQLite3Store) readAccount(ctx context.Context, txn *sql.Tx, addr string) (*Account, error) {
	query := fmt.Sprintf("SELECT %s FROM accounts WHERE address=?", strings.Join(accountCols, ","))
	row := txn.QueryRowContext(ctx, query, addr)

	var a Account
	err := row.Scan(&a.Address, &a.CreatedAt, &a.Signature, &a.ApprovedAt, &a.DeployedAt, &a.MigratedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) SaveAccountApprovalSignature(ctx context.Context, addr, sig string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	old, err := s.readAccount(ctx, tx, addr)
	if err != nil {
		return err
	}
	if old == nil {
		return fmt.Errorf("account not exists: %s", addr)
	}
	if old.ApprovedAt.Valid || old.Signature.Valid {
		return nil
	}

	query := "UPDATE accounts SET signature=? WHERE address=?"
	err = s.execOne(ctx, tx, query, sig, addr)
	if err != nil {
		return fmt.Errorf("UPDATE accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkAccountApproved(ctx context.Context, addr string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	old, err := s.readAccount(ctx, tx, addr)
	if err != nil {
		return err
	}
	if old == nil {
		return fmt.Errorf("account not exists: %s", addr)
	}

	err = s.execOne(ctx, tx, "UPDATE accounts SET approved_at=? WHERE address=?", time.Now().UTC(), addr)
	if err != nil {
		return fmt.Errorf("UPDATE accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkAccountDeployed(ctx context.Context, addr string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	old, err := s.readAccount(ctx, tx, addr)
	if err != nil {
		return err
	}
	if old == nil {
		return fmt.Errorf("account not exists: %s", addr)
	}
	if old.DeployedAt.Valid {
		return nil
	}

	err = s.execOne(ctx, tx, "UPDATE accounts SET deployed_at=? WHERE address=?", time.Now().UTC(), addr)
	if err != nil {
		return fmt.Errorf("UPDATE accounts %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListProposedAccountsWithSig(ctx context.Context) ([]*Account, error) {
	query := fmt.Sprintf("SELECT %s FROM accounts WHERE deployed_at IS NULL AND signature IS NOT NULL ORDER BY created_at ASC LIMIT 100", strings.Join(accountCols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var accounts []*Account
	for rows.Next() {
		var a Account
		err := rows.Scan(&a.Address, &a.CreatedAt, &a.Signature, &a.ApprovedAt, &a.DeployedAt, &a.MigratedAt)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, &a)
	}
	return accounts, nil
}

func (s *SQLite3Store) ListDeposits(ctx context.Context, chain int, holder string, state int, offset int64) ([]*Deposit, error) {
	return s.listDeposits(ctx, chain, holder, state, offset, false)
}

func (s *SQLite3Store) listDeposits(ctx context.Context, chain int, holder string, state int, offset int64, excludeChange bool) ([]*Deposit, error) {
	query := fmt.Sprintf("SELECT %s FROM deposits WHERE chain=? AND updated_at>=?", strings.Join(depositsCols, ","))
	params := []any{chain, time.Unix(0, offset).UTC()}
	if excludeChange {
		query += " AND is_change=FALSE"
	}
	if state > 0 {
		query += " AND state=?"
		params = append(params, state)
	}
	if holder != "" {
		query += " AND holder=?"
		params = append(params, holder)
	}
	query += " ORDER BY updated_at ASC LIMIT 100"
	return s.queryDeposits(ctx, nil, query, params)
}

func (s *SQLite3Store) listDepositsByCreatedAt(ctx context.Context, tx *sql.Tx, chain int, holder string, state int, offset int64, excludeChange bool) ([]*Deposit, error) {
	query := fmt.Sprintf("SELECT %s FROM deposits WHERE chain=? AND created_at>=?", strings.Join(depositsCols, ","))
	params := []any{chain, time.Unix(0, offset).UTC()}
	if state > 0 {
		query += " AND state=?"
		params = append(params, state)
	}
	if holder != "" {
		query += " AND holder=?"
		params = append(params, holder)
	}
	if excludeChange {
		query += " AND is_change=FALSE"
	}
	query += " ORDER BY created_at ASC, transaction_hash ASC, CAST(output_index AS INTEGER) ASC LIMIT 100"
	return s.queryDeposits(ctx, tx, query, params)
}

func (s *SQLite3Store) queryDeposits(ctx context.Context, tx *sql.Tx, query string, params []any) ([]*Deposit, error) {
	var rows *sql.Rows
	var err error
	if tx != nil {
		rows, err = tx.QueryContext(ctx, query, params...)
	} else {
		rows, err = s.db.QueryContext(ctx, query, params...)
	}
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var deposits []*Deposit
	for rows.Next() {
		var d Deposit
		err := rows.Scan(&d.TransactionHash, &d.OutputIndex, &d.AssetId, &d.AssetAddress, &d.Amount, &d.Receiver, &d.Sender, &d.State, &d.Chain, &d.Holder, &d.Category, &d.RequestId, &d.IsChange, &d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			return nil, err
		}
		deposits = append(deposits, &d)
	}
	return deposits, rows.Err()
}

func (s *SQLite3Store) CheckUnconfirmedDepositsForAssetAndHolder(ctx context.Context, holder, assetId string, offset time.Time) (bool, error) {
	query := "SELECT request_id FROM deposits WHERE holder=? AND asset_id=? AND state=? AND created_at<?"
	params := []any{holder, assetId, common.RequestStateInitial, offset}

	rows, err := s.db.QueryContext(ctx, query, params...)
	if err != nil {
		return false, err
	}
	defer util.CloseOrPanic(rows)

	return rows.Next(), nil
}

func (s *SQLite3Store) QueryDepositSentHashes(ctx context.Context, deposits []*Deposit) (map[string]string, error) {
	return s.queryDepositSentHashes(ctx, nil, deposits)
}

func (s *SQLite3Store) queryDepositSentHashes(ctx context.Context, tx *sql.Tx, deposits []*Deposit) (map[string]string, error) {
	sent := make(map[string]string)
	for _, d := range deposits {
		query := "SELECT transaction_hash FROM transactions WHERE spent_hash=?"
		var row *sql.Row
		if tx != nil {
			row = tx.QueryRowContext(ctx, query, d.TransactionHash)
		} else {
			row = s.db.QueryRowContext(ctx, query, d.TransactionHash)
		}

		var hash string
		err := row.Scan(&hash)
		if err == sql.ErrNoRows {
			continue
		} else if err != nil {
			return nil, err
		}
		sent[d.TransactionHash] = hash
	}
	return sent, nil
}

func (s *SQLite3Store) WritePendingDepositIfNotExists(ctx context.Context, d *Deposit) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	if d.State != common.RequestStateInitial {
		panic(d.State)
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT amount FROM deposits WHERE transaction_hash=? AND output_index=?", d.TransactionHash, d.OutputIndex)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("deposits", depositsCols), d.values()...)
	if err != nil {
		return fmt.Errorf("INSERT deposits %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) UpdateDepositRequestId(ctx context.Context, transactionHash string, outputIndex int64, oldRid, rid string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE deposits SET request_id=?, updated_at=? WHERE transaction_hash=? AND output_index=? AND request_id=? AND state=?"
	err = s.execOne(ctx, tx, query, rid, time.Now().UTC(), transactionHash, outputIndex, oldRid, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE deposits %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmPendingDeposit(ctx context.Context, transactionHash string, outputIndex int64, rid string, chain byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	query := "UPDATE deposits SET state=?, updated_at=? WHERE transaction_hash=? AND output_index=? AND request_id=? AND chain=? AND state=?"
	err = s.execOne(ctx, tx, query, common.RequestStateDone, time.Now().UTC(), transactionHash, outputIndex, rid, chain, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE deposits %v", err)
	}

	query = "UPDATE pending_deposits SET state=?, missing_since=NULL WHERE transaction_hash=? AND output_index=? AND chain=? AND state=?"
	_, err = tx.ExecContext(ctx, query, common.RequestStateDone, transactionHash, outputIndex, chain, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE pending_deposits %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ConfirmFullySignedTransactionApproval(ctx context.Context, hash, spentHash, spentRaw, cancelHash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()

	query := "UPDATE transactions SET spent_hash=?, spent_raw=?, updated_at=? WHERE transaction_hash=? AND state=? AND spent_hash IS NULL"
	err = s.execOne(ctx, tx, query, spentHash, spentRaw, now, hash, common.RequestStateDone)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	if cancelHash != "" {
		query := "UPDATE transactions SET state=?, updated_at=? WHERE transaction_hash=? AND state=?"
		err = s.execOne(ctx, tx, query, common.RequestStateFailed, now, cancelHash, common.RequestStateDone)
		if err != nil {
			return fmt.Errorf("UPDATE transactions %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListFullySignedTransactionApprovals(ctx context.Context, chain byte) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE chain=? AND state=? AND spent_hash IS NULL ORDER BY created_at ASC", strings.Join(transactionCols, ","))
	rows, err := s.db.QueryContext(ctx, query, chain, common.RequestStateDone)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var approvals []*Transaction
	for rows.Next() {
		var t Transaction
		err = rows.Scan(&t.TransactionHash, &t.RawTransaction, &t.Chain, &t.Holder, &t.Signer, &t.State, &t.SpentHash, &t.SpentRaw, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, &t)
	}
	return approvals, nil
}

func (s *SQLite3Store) ListPendingTransactionApprovals(ctx context.Context, chain byte) ([]*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE chain=? AND state=? ORDER BY created_at ASC", strings.Join(transactionCols, ","))
	rows, err := s.db.QueryContext(ctx, query, chain, common.RequestStatePending)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var approvals []*Transaction
	for rows.Next() {
		var t Transaction
		err = rows.Scan(&t.TransactionHash, &t.RawTransaction, &t.Chain, &t.Holder, &t.Signer, &t.State, &t.SpentHash, &t.SpentRaw, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, &t)
	}
	return approvals, nil
}

func (s *SQLite3Store) CountUnfinishedTransactionApprovalsForHolder(ctx context.Context, holder string) (int, error) {
	query := "SELECT COUNT(*) FROM transactions WHERE holder=? AND state IN (?, ?)"
	row := s.db.QueryRowContext(ctx, query, holder, common.RequestStateInitial, common.RequestStatePending)

	var count int
	err := row.Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

func (s *SQLite3Store) WriteTransactionApprovalIfNotExists(ctx context.Context, approval *Transaction) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT raw_transaction FROM transactions WHERE transaction_hash=?", approval.TransactionHash)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("transactions", transactionCols), approval.values()...)
	if err != nil {
		return fmt.Errorf("INSERT transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) RevokeTransactionApproval(ctx context.Context, transactionHash string, sigBase64 string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, state=?, updated_at=? WHERE transaction_hash=? AND state=?",
		sigBase64, common.RequestStateFailed, time.Now().UTC(), transactionHash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) AddTransactionPartials(ctx context.Context, transactionHash string, raw string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, updated_at=? WHERE transaction_hash=? AND state=?",
		raw, time.Now().UTC(), transactionHash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) MarkTransactionApprovalPaid(ctx context.Context, transactionHash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE transactions SET state=?, updated_at=? WHERE transaction_hash=? AND state=?",
		common.RequestStatePending, time.Now().UTC(), transactionHash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) UpdateTransactionApprovalRequestTime(ctx context.Context, transactionHash string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE transactions SET updated_at=? WHERE transaction_hash=? AND state=?",
		time.Now().UTC(), transactionHash, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) FinishTransactionSignatures(ctx context.Context, transactionHash string, raw string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, state=?, updated_at=? WHERE transaction_hash=? AND state IN (?, ?)",
		raw, common.RequestStateDone, time.Now().UTC(), transactionHash, common.RequestStateInitial, common.RequestStatePending)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT state FROM recoveries WHERE transaction_hash=?", transactionHash)
	if err != nil {
		return err
	}
	if existed {
		err = s.updateRecoveryState(ctx, tx, transactionHash, raw, common.RequestStateDone)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadTransactionApproval(ctx context.Context, hash string) (*Transaction, error) {
	query := fmt.Sprintf("SELECT %s FROM transactions WHERE transaction_hash=? OR spent_hash=?", strings.Join(transactionCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash, hash)

	var t Transaction
	err := row.Scan(&t.TransactionHash, &t.RawTransaction, &t.Chain, &t.Holder, &t.Signer, &t.State, &t.SpentHash, &t.SpentRaw, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &t, err
}

func (s *SQLite3Store) WriteAccountantKeys(ctx context.Context, crv byte, keys map[string]*btcec.PrivateKey) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	for addr, priv := range keys {
		pub := hex.EncodeToString(priv.PubKey().SerializeCompressed())
		cols := []string{"public_key", "private_key", "address", "curve", "created_at"}
		vals := []any{pub, hex.EncodeToString(priv.Serialize()), addr, crv, time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("accountants", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT accountants %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadAccountantPrivateKey(ctx context.Context, address string) (string, error) {
	query := "SELECT private_key FROM accountants WHERE address=?"
	row := s.db.QueryRowContext(ctx, query, address)

	var key string
	err := row.Scan(&key)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return key, err
}

func (s *SQLite3Store) WriteObserverKeys(ctx context.Context, crv byte, publics map[string]string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	for pub, code := range publics {
		cols := []string{"public_key", "curve", "chain_code", "created_at"}
		vals := []any{pub, crv, code, time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("observers", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT observers %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadObserverKey(ctx context.Context, crv byte) (string, []byte, error) {
	var public, chainCode string
	row := s.db.QueryRowContext(ctx, "SELECT public_key,chain_code FROM observers WHERE curve=? LIMIT 1", crv)
	err := row.Scan(&public, &chainCode)
	if err == sql.ErrNoRows {
		return "", nil, nil
	}
	return public, common.DecodeHexOrPanic(chainCode), err
}

func (s *SQLite3Store) DeleteObserverKey(ctx context.Context, pub string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	err = s.execOne(ctx, tx, "DELETE FROM observers WHERE public_key=?", pub)
	if err != nil {
		return fmt.Errorf("DELETE observers %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadAssetMeta(ctx context.Context, id string) (*Asset, error) {
	query := fmt.Sprintf("SELECT %s FROM assets WHERE asset_id=? OR mixin_id=?", strings.Join(assetCols, ","))
	row := s.db.QueryRowContext(ctx, query, id, id)

	var a Asset
	err := row.Scan(&a.AssetId, &a.MixinId, &a.AssetKey, &a.Symbol, &a.Name, &a.Decimals, &a.Chain, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *SQLite3Store) WriteAssetMeta(ctx context.Context, asset *Asset) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := []any{asset.AssetId, asset.MixinId, asset.AssetKey, asset.Symbol, asset.Name, asset.Decimals, asset.Chain, asset.CreatedAt}
	err = s.execOne(ctx, tx, buildInsertionSQL("assets", assetCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT assets %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteInitialRecovery(ctx context.Context, recovery *Recovery) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	vals := recovery.values()
	err = s.execOne(ctx, tx, buildInsertionSQL("recoveries", recoveryCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT recoveries %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) UpdateRecoveryState(ctx context.Context, address, hash, raw string, state int) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT state FROM recoveries WHERE address=? AND transaction_hash=?", address, hash)
	if err != nil || !existed {
		return err
	}
	err = s.updateRecoveryState(ctx, tx, hash, raw, state)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) updateRecoveryState(ctx context.Context, tx *sql.Tx, hash, raw string, state int) error {
	switch state {
	case common.RequestStatePending:
		return s.execOne(ctx, tx, "UPDATE recoveries SET state=?, raw_transaction=?, updated_at=? WHERE transaction_hash=? AND state=?",
			state, raw, time.Now().UTC(), hash, common.RequestStateInitial)
	case common.RequestStateDone:
		return s.execOne(ctx, tx, "UPDATE recoveries SET state=?, raw_transaction=?, updated_at=? WHERE transaction_hash=? AND state IN (?, ?)",
			state, raw, time.Now().UTC(), hash, common.RequestStateInitial, common.RequestStatePending)
	default:
		panic(state)
	}
}

func (s *SQLite3Store) CloseRecoveryWithObserverKey(ctx context.Context, address, hash, sigRaw string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	now := time.Now().UTC()
	err = s.execOne(ctx, tx, "UPDATE recoveries SET state=?, updated_at=? WHERE address=? AND transaction_hash=? AND state=?",
		common.RequestStateFailed, now, address, hash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE recoveries %v", err)
	}
	err = s.execOne(ctx, tx, "UPDATE transactions SET raw_transaction=?, state=?, updated_at=? WHERE transaction_hash=? AND state=?",
		sigRaw, common.RequestStateFailed, now, hash, common.RequestStateInitial)
	if err != nil {
		return fmt.Errorf("UPDATE transactions %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) ReadRecovery(ctx context.Context, address, hash string) (*Recovery, error) {
	r, err := s.ReadRecoveryByHash(ctx, hash)
	if err != nil || r == nil {
		return nil, err
	}
	if r.Address != address {
		panic(r.Address)
	}
	return r, nil
}

func (s *SQLite3Store) ReadRecoveryByHash(ctx context.Context, hash string) (*Recovery, error) {
	query := fmt.Sprintf("SELECT %s FROM recoveries WHERE transaction_hash=?", strings.Join(recoveryCols, ","))
	row := s.db.QueryRowContext(ctx, query, hash)

	var r Recovery
	err := row.Scan(&r.Address, &r.Chain, &r.Holder, &r.Observer, &r.RawTransaction, &r.TransactionHash, &r.State, &r.IsInheritance, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &r, err
}

func (s *SQLite3Store) ListInitialRecoveries(ctx context.Context, offset int64) ([]*Recovery, error) {
	query := fmt.Sprintf("SELECT %s FROM recoveries WHERE state=? AND created_at>=? ORDER BY created_at ASC LIMIT 100", strings.Join(recoveryCols, ","))
	rows, err := s.db.QueryContext(ctx, query, common.RequestStateInitial, time.Unix(0, offset))
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var recoveries []*Recovery
	for rows.Next() {
		var r Recovery
		err = rows.Scan(&r.Address, &r.Chain, &r.Holder, &r.Observer, &r.RawTransaction, &r.TransactionHash, &r.State, &r.IsInheritance, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			return nil, err
		}
		recoveries = append(recoveries, &r)
	}
	return recoveries, nil
}

func (s *SQLite3Store) UpsertNodeStats(ctx context.Context, appId, typ, stats string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	ns := NodeStats{
		AppId:     appId,
		Type:      typ,
		Stats:     stats,
		UpdatedAt: time.Now().UTC(),
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT app_id FROM nodes WHERE app_id=? AND node_type=?", appId, typ)
	if err != nil {
		return err
	}
	if existed {
		err = s.execOne(ctx, tx, "UPDATE nodes SET stats=?, updated_at=? WHERE app_id=? AND node_type=?",
			ns.Stats, ns.UpdatedAt, appId, typ)
		if err != nil {
			return fmt.Errorf("UPDATE nodes %v", err)
		}
	} else {
		vals := ns.values()
		err = s.execOne(ctx, tx, buildInsertionSQL("nodes", nodeCols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT nodes %v", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3Store) ListNodeStats(ctx context.Context, typ string) ([]*NodeStats, error) {
	query := fmt.Sprintf("SELECT %s FROM nodes WHERE node_type=? ORDER BY updated_at DESC", strings.Join(nodeCols, ","))
	rows, err := s.db.QueryContext(ctx, query, typ)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var nodes []*NodeStats
	for rows.Next() {
		var n NodeStats
		err = rows.Scan(&n.AppId, &n.Type, &n.Stats, &n.UpdatedAt)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, &n)
	}
	return nodes, nil
}

func (s *SQLite3Store) ReadCache(ctx context.Context, k string, d time.Duration) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	row := s.db.QueryRowContext(ctx, "SELECT value,created_at FROM caches WHERE key=?", k)
	var value string
	var createdAt time.Time
	err := row.Scan(&value, &createdAt)
	if err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", err
	}
	if time.Since(createdAt) > d {
		return "", nil
	}
	return value, nil
}

func (s *SQLite3Store) WriteCache(ctx context.Context, k, v string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	threshold := time.Now().Add(-cacheTTL).UTC()
	_, err = tx.ExecContext(ctx, "DELETE FROM caches WHERE created_at<?", threshold)
	if err != nil {
		return err
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT key FROM caches WHERE key=?", k)
	if err != nil {
		return err
	}
	if existed {
		err = s.execOne(ctx, tx, "UPDATE caches SET value=?,created_at=? WHERE key=?",
			v, time.Now().UTC(), k)
		if err != nil {
			return fmt.Errorf("UPDATE caches %v", err)
		}

	} else {
		cols := []string{"key", "value", "created_at"}
		vals := []any{k, v, time.Now().UTC()}
		err = s.execOne(ctx, tx, buildInsertionSQL("caches", cols), vals...)
		if err != nil {
			return fmt.Errorf("INSERT caches %v", err)
		}
	}
	return tx.Commit()
}

func (s SQLite3Store) writeBlockCheckpoint(ctx context.Context, chain byte, checkpoint int64) error {
	return s.WriteProperty(ctx, depositCheckpointKey(chain), fmt.Sprint(checkpoint))
}

func (s *SQLite3Store) WritePendingDepositRecord(ctx context.Context, d *PendingDeposit) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	if d.State != common.RequestStateInitial {
		panic(d.State)
	}

	existed, err := s.checkExistence(ctx, tx, "SELECT amount FROM pending_deposits WHERE chain=? AND transaction_hash=? AND output_index=?", d.Chain, d.TransactionHash, d.OutputIndex)
	if err != nil || existed {
		return err
	}

	existed, err = s.checkExistence(ctx, tx, "SELECT amount FROM deposits WHERE transaction_hash=? AND output_index=? AND chain=? AND state=?", d.TransactionHash, d.OutputIndex, d.Chain, common.RequestStateDone)
	if err != nil || existed {
		return err
	}

	err = s.execOne(ctx, tx, buildInsertionSQL("pending_deposits", pendingDepositsCols), d.values()...)
	if err != nil {
		return fmt.Errorf("INSERT pending_deposits %v", err)
	}

	return tx.Commit()
}

type pendingDepositObservation struct {
	TransactionHash string
	OutputIndex     int64
	MissingSince    sql.NullTime
}

// Reconciliation must include records beyond the public API's first 100 rows.
func (s *SQLite3Store) listPendingDepositObservations(ctx context.Context, chain byte) ([]pendingDepositObservation, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT transaction_hash, output_index, missing_since FROM pending_deposits WHERE chain=? AND state=?", chain, common.RequestStateInitial)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	var observations []pendingDepositObservation
	for rows.Next() {
		var d pendingDepositObservation
		if err := rows.Scan(&d.TransactionHash, &d.OutputIndex, &d.MissingSince); err != nil {
			return nil, err
		}
		observations = append(observations, d)
	}
	return observations, rows.Err()
}

func (s *SQLite3Store) updatePendingDepositMissingSince(ctx context.Context, chain byte, d pendingDepositObservation, since sql.NullTime) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, err := s.db.ExecContext(ctx, "UPDATE pending_deposits SET missing_since=? WHERE chain=? AND transaction_hash=? AND output_index=? AND state=? AND missing_since IS ?",
		since, chain, d.TransactionHash, d.OutputIndex, common.RequestStateInitial, d.MissingSince)
	return err
}

func (s *SQLite3Store) deleteMissingPendingDeposit(ctx context.Context, chain byte, d pendingDepositObservation) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Do not delete an observation confirmed or refreshed during the RPC lookup,
	// or one already picked up by the independent formal deposit scanner.
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending_deposits
		WHERE chain=? AND transaction_hash=? AND output_index=? AND state=? AND missing_since=?
		AND NOT EXISTS (SELECT 1 FROM deposits WHERE chain=? AND transaction_hash=? AND output_index=?)`,
		chain, d.TransactionHash, d.OutputIndex, common.RequestStateInitial, d.MissingSince,
		chain, d.TransactionHash, d.OutputIndex)
	return err
}

func (s *SQLite3Store) ListPendingDeposits(ctx context.Context, chain int, holder string, offset int64) ([]*PendingDeposit, error) {
	query := fmt.Sprintf("SELECT %s FROM pending_deposits WHERE chain=? AND state=? AND created_at>=?", strings.Join(pendingDepositsCols, ","))
	params := []any{chain, common.RequestStateInitial, time.Unix(0, offset).UTC()}
	if holder != "" {
		query += " AND holder=?"
		params = append(params, holder)
	}
	query += " ORDER BY created_at ASC, transaction_hash ASC, output_index ASC LIMIT 100"
	rows, err := s.db.QueryContext(ctx, query, params...)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(rows)

	deposits := make([]*PendingDeposit, 0)
	for rows.Next() {
		var d PendingDeposit
		err := rows.Scan(&d.TransactionHash, &d.OutputIndex, &d.AssetId, &d.AssetAddress, &d.Amount, &d.Receiver, &d.Sender, &d.State, &d.Chain, &d.Holder, &d.CreatedAt)
		if err != nil {
			return nil, err
		}
		deposits = append(deposits, &d)
	}
	return deposits, rows.Err()
}

func (s *SQLite3Store) deleteExpiredEthereumPendingDeposits(ctx context.Context, chain byte, cutoff time.Time) error {
	switch chain {
	case common.SafeChainEthereum, common.SafeChainPolygon:
	default:
		return fmt.Errorf("invalid EVM pending deposit chain %d", chain)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Expiry only ends the observation; it does not invalidate a formal deposit.
	_, err := s.db.ExecContext(ctx, "DELETE FROM pending_deposits WHERE chain=? AND state=? AND created_at<=?",
		chain, common.RequestStateInitial, cutoff.UTC())
	return err
}
