package solana

import (
	"context"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

func TestRPCGetTransaction(t *testing.T) {
	c := NewClient(rpc.MainNetBeta.RPC, rpc.MainNetBeta.WS)
	r, err := c.RPCGetTransaction(context.TODO(), "2nijNeL8mYp97HgJbv6bi5bfa6CJNttpZKCXM7SRnQ5ZvKcT3GjRqnVkzf8ardVx3h4yKZ8UD7c5GJn2fh8r5Ajm")
	if err != nil {
		t.Fatal(err)
	}

	tx, err := r.Transaction.GetTransaction()
	if err != nil {
		t.Fatal(err)
	}

	if err := c.processTransactionWithAddressLookups(context.TODO(), tx); err != nil {
		t.Fatal(err)
	}

	t.Log("instructions", len(tx.Message.Instructions), len(tx.Message.AccountKeys))

	if r.Meta != nil {
		t.Log("loaded addresses", len(r.Meta.LoadedAddresses.ReadOnly)+len(r.Meta.LoadedAddresses.Writable))
		t.Log("balance changes", len(r.Meta.PreBalances), len(r.Meta.PostBalances))

		t.Log("inner instructions", len(r.Meta.InnerInstructions))

		for _, i := range r.Meta.InnerInstructions {
			t.Log("inner instruction", i.Index, len(i.Instructions))
		}

		for _, token := range r.Meta.PreTokenBalances {
			t.Log("pre token balance", token.Mint, token.Owner.String(), token.UiTokenAmount.Decimals)
		}
	}
}

func TestEmptyAddress(t *testing.T) {
	var pk solana.PublicKey
	t.Log(pk.String())
}
