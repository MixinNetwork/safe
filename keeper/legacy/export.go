package legacy

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/safe/keeper/store"
)

func (s *SQLite3Store) ExportData(ctx context.Context, export *store.SQLite3Store) error {
	fmt.Println("Reading data from database...")
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

	err = export.Export(ctx, store.ExportData{
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
	if err != nil {
		return err
	}

	fmt.Println("Export successfully!")
	return nil
}
