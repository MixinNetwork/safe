package mixin

import (
	"fmt"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

type Input struct {
	TransactionHash string
	Index           uint32
	Amount          decimal.Decimal
	Asset           crypto.Hash
	Mask            crypto.Key
}

type Output struct {
	Address *common.Address
	Amount  decimal.Decimal
}

func ParseTransactionDepositOutput(holder, signer, observer string, mtx *common.VersionedTransaction, index int) (*Input, string) {
	if len(mtx.Outputs) < index+1 {
		return nil, ""
	}
	out := mtx.Outputs[index]
	if out.Type != common.OutputTypeScript {
		return nil, ""
	}
	if out.Script.String() != "fffe01" {
		return nil, ""
	}
	if len(out.Keys) != 1 {
		return nil, ""
	}
	addr := BuildAddress(holder, signer, observer)
	pub := crypto.ViewGhostOutputKey(out.Keys[0], &addr.PrivateViewKey, &out.Mask, uint64(index))
	if pub.String() != addr.PublicSpendKey.String() {
		return nil, ""
	}
	input := &Input{
		TransactionHash: mtx.PayloadHash().String(),
		Index:           uint32(index),
		Amount:          decimal.RequireFromString(out.Amount.String()),
		Asset:           mtx.Asset,
		Mask:            out.Mask,
	}
	return input, addr.String()
}

func BuildPartiallySignedTransaction(mainInputs []*Input, outputs []*Output, rid string, holder, signer, observer string) (*common.VersionedTransaction, error) {
	var input, output decimal.Decimal
	tx := common.NewTransactionV4(mainInputs[0].Asset)
	for _, in := range mainInputs {
		if in.Asset != tx.Asset {
			panic(in.Asset.String())
		}
		input = input.Add(in.Amount)
		hash, err := crypto.HashFromString(in.TransactionHash)
		if err != nil {
			panic(in.TransactionHash)
		}
		tx.AddInput(hash, int(in.Index))
	}

	si := crypto.NewHash([]byte("SEED:" + holder + signer + observer + rid))
	si = crypto.NewHash(append(tx.AsVersioned().PayloadMarshal(), si[:]...))
	for i, out := range outputs {
		output = output.Add(out.Amount)
		script := common.NewThresholdScript(1)
		amount := common.NewIntegerFromString(out.Amount.String())
		os := fmt.Sprintf("%x:%s:%s:%d", si[:], out.Address.String(), out.Amount.String(), i)
		seed := crypto.NewHash([]byte(os))
		tx.AddScriptOutput([]*common.Address{out.Address}, script, amount, append(seed[:], seed[:]...))
	}

	if input.Cmp(output) < 0 {
		return nil, bitcoin.BuildInsufficientInputError("main", input.String(), output.String())
	}
	change := input.Sub(output)
	addr := BuildAddress(holder, signer, observer)
	if change.IsPositive() {
		script := common.NewThresholdScript(1)
		amount := common.NewIntegerFromString(change.String())
		seed := crypto.NewHash([]byte(fmt.Sprintf("%x:%d", si[:], len(outputs))))
		tx.AddScriptOutput([]*common.Address{addr}, script, amount, append(seed[:], seed[:]...))
	}

	tx.Extra = uuid.Must(uuid.FromString(rid)).Bytes()
	return tx.AsVersioned(), nil
}

func ParsePartiallySignedTransaction(b []byte) (*common.VersionedTransaction, error) {
	return common.UnmarshalVersionedTransaction(b)
}
