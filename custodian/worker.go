package custodian

import (
	"context"

	"github.com/MixinNetwork/trusted-group/mtg"
)

const (
	XINAssetId = "c94ac88f-4671-3976-b60a-09064f1811e8"

	// domain do the first key, next should be from the first key
	CustodianActionRefreshKey = 1
	CustodianActionDistribute = 2

	// every signer node will send this to the mtg
	// everyday at a specific time
	// then at some point, a random output will cause
	// all signer nodes to finalize the works
	CustodianActionVoteWorks = 3
	// then the signer mtg send this action to keeper mtg
	// the custodian will process this then
	CustodianActionFinalizeWorks = 4
)

type Worker struct {
	store           *SQLite3Store
	signerAssetId   string
	keeperAssetId   string
	observerAssetId string
}

func NewWorker(s *SQLite3Store) *Worker {
	return &Worker{
		store: s,
	}
}

func (worker *Worker) ProcessOutput(ctx context.Context, out *mtg.Action) ([]*mtg.Transaction, string) {
	return nil, ""
}

func (worker *Worker) Boot(ctx context.Context) {
	go worker.loopKernelMintDistributions(ctx)
}

func (worker *Worker) handleRefreshKey() {
	// domain signature verification
	// send a request to signer keygen, ed25519 mixin
	// receive keygen from signer and store the key
	// custodian use public derivation of spend key
}

func (worker *Worker) loopKernelMintDistributions(ctx context.Context) {
	//for {
	// loop read mint distributions to the custodian key
	// for new distribution, send the mint to keeper MTG with custodian action distribute
	//}
}
