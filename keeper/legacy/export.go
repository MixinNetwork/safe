package legacy

import (
	"context"
)

func (s *SQLite3Store) ExportData(ctx context.Context, path string) error {
	requests, err := s.listRequests(ctx)
	if err != nil {
		return err
	}

	infos, err := s.listLatestNetworkInfos(ctx)
	if err != nil {
		return err
	}

	ops, err := s.listLatestOperationParams(ctx)
	if err != nil {
		return err
	}

	assets, err := s.listAssets(ctx)
	if err != nil {
		return err
	}

	keys, err := s.listKeys(ctx)
	if err != nil {
		return err
	}

	proposals, err := s.listProposals(ctx)
	if err != nil {
		return err
	}

	safes, err := s.listSafes(ctx)
	if err != nil {
		return err
	}

	outputs, err := s.listBitcoinOutputs(ctx)
	if err != nil {
		return err
	}

	balances, err := s.listEthereumBalances(ctx)
	if err != nil {
		return err
	}

	deposits, err := s.listDeposits(ctx)
	if err != nil {
		return err
	}

	txs, err := s.listTransactions(ctx)
	if err != nil {
		return err
	}

	signatures, err := s.listSignatureRequests(ctx)
	if err != nil {
		return err
	}

	properties, err := s.listProperties(ctx)
	if err != nil {
		return err
	}

	return nil
}
