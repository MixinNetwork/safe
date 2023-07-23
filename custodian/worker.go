package custodian

import (
	"context"

	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	// domain do the first key, next should be from the first key
	CustodianActionRefreshKey = 1
	CustodianActionDistribute = 2
)

type Worker struct {
	store *SQLite3Store
}

func NewWorker(s *SQLite3Store) *Worker {
	return &Worker{
		store: s,
	}
}

func (worker *Worker) ProcessOutput(ctx context.Context, out *mtg.Output) {
}

func (worker *Worker) ProcessCollectibleOutput(context.Context, *mtg.CollectibleOutput) {}

func (worker *Worker) Boot(ctx context.Context) {
	go worker.loopKernelMintDistributions(ctx)
}

func (worker *Worker) loopKernelMintDistributions(ctx context.Context) {
	//for {
	// loop read mint distributions to the custodian key
	// for new distribution, send the mint to keeper MTG with custodian action distribute
	//}
}
