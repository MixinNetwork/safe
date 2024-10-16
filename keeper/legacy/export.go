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
	fmt.Printf("Read %d requests\n", len(requests))

	infos, err := s.listLatestNetworkInfos(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d network_infos\n", len(infos))

	ops, err := s.listLatestOperationParams(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d operation_params\n", len(ops))

	assets, err := s.listAssets(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d assets\n", len(assets))

	keys, err := s.listKeys(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d keys\n", len(keys))

	proposals, err := s.listProposals(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d safe_proposals\n", len(proposals))

	safes, err := s.listSafes(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d safes\n", len(safes))

	outputs, err := s.listBitcoinOutputs(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d bitcoin_outputs\n", len(outputs))

	balances, err := s.listEthereumBalances(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d ethereum_balances\n", len(balances))

	deposits, err := s.listDeposits(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d deposits\n", len(deposits))

	txs, err := s.listTransactions(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d transactions\n", len(txs))

	signatures, err := s.listSignatureRequests(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d signature requests\n", len(signatures))

	properties, err := s.listProperties(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d properties\n", len(properties))

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
