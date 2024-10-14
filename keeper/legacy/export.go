package legacy

import (
	"context"
)

func (s *SQLite3Store) ExportData(ctx context.Context, path string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	requests, err := s.listRequests(ctx, tx)
	if err != nil {
		return err
	}

	infos, err := s.listLatestNetworkInfos(ctx, tx)
	if err != nil {
		return err
	}

	ops, err := s.listLatestOperationParams(ctx, tx)
	if err != nil {
		return err
	}

	assets, err := s.listAssets(ctx, tx)
	if err != nil {
		return err
	}

	keys, err := s.listKeys(ctx, tx)
	if err != nil {
		return err
	}

	proposals, err := s.listProposals(ctx, tx)
	if err != nil {
		return err
	}

	safes, err := s.listSafes(ctx, tx)
	if err != nil {
		return err
	}

	outputs, err := s.listBitcoinOutputs(ctx, tx)
	if err != nil {
		return err
	}

	balances, err := s.listEthereumBalances(ctx, tx)
	if err != nil {
		return err
	}

	deposits, err := s.listDeposits(ctx, tx)
	if err != nil {
		return err
	}

	txs, err := s.listTransactions(ctx, tx)
	if err != nil {
		return err
	}

	signatures, err := s.listSignatureRequests(ctx, tx)
	if err != nil {
		return err
	}

	properties, err := s.listProperties(ctx, tx)
	if err != nil {
		return err
	}

	return nil
}
