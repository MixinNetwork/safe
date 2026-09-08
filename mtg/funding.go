package mtg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"

	mixinCommon "github.com/MixinNetwork/mixin/common"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/fox-one/mixin-sdk-go/v3/mixinnet"
	"github.com/shopspring/decimal"
)

// CreateAndSignMultisigTransaction creates the deterministic transaction that
// returns this funding request from the custodian to the MTG, then adds the
// current observer's multisig signature.
func (funding *FundingRequest) CreateAndSignMultisigTransaction(ctx context.Context, client *mixin.Client, spendPrivateKey string) (*mixin.SafeMultisigRequest, error) {
	custodian, receiver, err := funding.validateMultisigTransaction(client)
	if err != nil {
		return nil, err
	}
	members := custodian.Members()
	sort.Strings(members)
	utxos, err := client.SafeListUtxos(ctx, mixin.SafeListUtxoOption{
		Members:   members,
		Threshold: custodian.Threshold,
		Asset:     funding.AssetId,
		State:     mixin.SafeUtxoStateUnspent,
		Limit:     500,
		Order:     "ASC",
	})
	if err != nil {
		return nil, err
	}
	utxos, err = selectFundingUTXOs(utxos, funding.Amount)
	if err != nil {
		return nil, err
	}
	builder := mixin.NewSafeTransactionBuilder(utxos)
	builder.Hint = funding.TraceId
	builder.Memo = EncodeMixinExtraBase64(funding.AppId, funding.ReturnMemo)
	transaction, err := client.MakeTransaction(ctx, builder, []*mixin.TransactionOutput{{
		Address: receiver,
		Amount:  funding.Amount,
	}})
	if err != nil {
		return nil, err
	}
	data, err := transaction.DumpData()
	if err != nil {
		return nil, err
	}
	expected, err := mixinCommon.UnmarshalVersionedTransaction(data)
	if err != nil {
		return nil, err
	}
	raw := hex.EncodeToString(data)
	request, err := client.SafeCreateMultisigRequest(ctx, &mixin.SafeTransactionRequestInput{
		RequestID:      funding.TraceId,
		RawTransaction: raw,
	})
	if err != nil {
		return nil, err
	}
	if err := validateFundingMultisigRequest(request, expected, custodian, funding.TraceId); err != nil {
		return nil, err
	}
	if slices.Contains(request.Signers, client.ClientID) {
		return request, nil
	}

	index, err := fundingSignerIndex(request.Senders, client.ClientID)
	if err != nil {
		return nil, err
	}
	key, err := mixinnet.KeyFromString(spendPrivateKey)
	if err != nil {
		return nil, err
	}
	transaction, err = mixinnet.TransactionFromRaw(request.RawTransaction)
	if err != nil {
		return nil, err
	}
	if len(request.Views) != len(transaction.Inputs) {
		return nil, fmt.Errorf("invalid custodian multisig views %d/%d", len(request.Views), len(transaction.Inputs))
	}
	if err := mixin.SafeSignTransaction(transaction, key, request.Views, index); err != nil {
		return nil, err
	}
	signedRaw, err := transaction.Dump()
	if err != nil {
		return nil, err
	}
	signed, err := client.SafeSignMultisigRequest(ctx, &mixin.SafeTransactionRequestInput{
		RequestID:      request.RequestID,
		RawTransaction: signedRaw,
	})
	if err != nil {
		return nil, err
	}
	if err := validateFundingMultisigRequest(signed, expected, custodian, funding.TraceId); err != nil {
		return nil, err
	}
	if !slices.Contains(signed.Signers, client.ClientID) {
		return nil, fmt.Errorf("custodian multisig request %s did not record signer %s", request.RequestID, client.ClientID)
	}
	return signed, nil
}

func (funding *FundingRequest) validateMultisigTransaction(client *mixin.Client) (*mixin.MixAddress, *mixin.MixAddress, error) {
	scaled := funding.Amount.Mul(decimal.New(1, 8))
	if funding.Amount.Cmp(decimal.Zero) <= 0 || !scaled.IsInteger() || !scaled.BigInt().IsUint64() {
		return nil, nil, fmt.Errorf("invalid funding amount %s", funding.Amount)
	}
	if !bytes.Equal(funding.ReturnMemo, EncodeFundingReturnMemo(funding.TraceId)) {
		return nil, nil, fmt.Errorf("invalid funding return memo %s", funding.TraceId)
	}
	custodian, err := mixin.MixAddressFromString(funding.CustodianAddress)
	if err != nil || custodian.Threshold <= 1 {
		return nil, nil, fmt.Errorf("invalid custodian address %s", funding.CustodianAddress)
	}
	receiver, err := mixin.MixAddressFromString(funding.ReturnAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid funding return address %s", funding.ReturnAddress)
	}
	if custodian.String() == receiver.String() {
		return nil, nil, fmt.Errorf("funding return address equals custodian address")
	}
	if !slices.Contains(custodian.Members(), client.ClientID) {
		return nil, nil, fmt.Errorf("observer %s is not a custodian member", client.ClientID)
	}
	return custodian, receiver, nil
}

func validateFundingMultisigRequest(request *mixin.SafeMultisigRequest, expected *mixinCommon.VersionedTransaction, custodian *mixin.MixAddress, requestId string) error {
	if request == nil || request.RequestID != requestId || request.RevokedBy != "" {
		return fmt.Errorf("invalid custodian multisig request")
	}
	if request.SendersThreshold != custodian.Threshold || mixinnet.HashMembers(request.Senders) != mixinnet.HashMembers(custodian.Members()) {
		return fmt.Errorf("invalid custodian multisig members %s", request.RequestID)
	}
	_, err := CheckMultisigRequestRawTransaction(request, expected)
	return err
}

func selectFundingUTXOs(utxos []*mixin.SafeUtxo, amount decimal.Decimal) ([]*mixin.SafeUtxo, error) {
	const maxInputs = 255
	selected := make([]*mixin.SafeUtxo, 0, len(utxos))
	total := decimal.Zero
	for _, utxo := range utxos {
		if utxo == nil || utxo.InscriptionHash.HasValue() {
			continue
		}
		if len(selected) == maxInputs {
			break
		}
		selected = append(selected, utxo)
		total = total.Add(utxo.Amount)
		if total.Cmp(amount) >= 0 {
			return selected, nil
		}
	}
	return nil, fmt.Errorf("insufficient custodian outputs for funding %s: %s", amount, total)
}

func fundingSignerIndex(senders []string, clientId string) (uint16, error) {
	members := append([]string(nil), senders...)
	sort.Strings(members)
	for i := 1; i < len(members); i++ {
		if members[i] == members[i-1] {
			return 0, fmt.Errorf("duplicate custodian member %s", members[i])
		}
	}
	index := slices.Index(members, clientId)
	if index < 0 {
		return 0, fmt.Errorf("observer %s is not a custodian member", clientId)
	}
	return uint16(index), nil
}
