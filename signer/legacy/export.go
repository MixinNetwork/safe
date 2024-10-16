package legacy

import (
	"context"
	"fmt"

	"github.com/MixinNetwork/safe/signer"
)

func (s *SQLite3Store) ExportData(ctx context.Context, export *signer.SQLite3Store) error {
	fmt.Println("Reading data from database...")

	properties, err := s.listProperties(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d properties\n", len(properties))

	sessions, err := s.listSessions(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d sessions\n", len(sessions))

	signers, err := s.listSessionSigners(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d session_signers\n", len(signers))

	works, err := s.listSessionWorks(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Read %d session_works\n", len(works))

	err = export.Export(ctx, signer.ExportData{
		Properties:     properties,
		Sessions:       sessions,
		SessionSigners: signers,
		SessionWorks:   works,
	})
	if err != nil {
		return err
	}

	fmt.Println("Export successfully!")
	return nil
}
