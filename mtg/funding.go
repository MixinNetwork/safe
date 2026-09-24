package mtg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	mixinCommon "github.com/MixinNetwork/mixin/common"
	"github.com/fox-one/mixin-sdk-go/v3"
	"github.com/fox-one/mixin-sdk-go/v3/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const fundingMultisigMessagePurpose = "custodian-funding-multisig"

// CreateAndSignMultisigTransaction creates the deterministic transaction that
// returns this funding request from the custodian to the MTG, then adds the
// current observer's multisig signature.
func (funding *FundingRequest) CreateAndSignMultisigTransaction(ctx context.Context, client *mixin.Client, spendPrivateKey string) (*mixin.SafeMultisigRequest, error) {
	custodian, receiver, err := funding.validateMultisigTransaction(client)
	if err != nil {
		return nil, err
	}
	// A retry must use the original inputs even after they become signed/spent.
	// Rebuild the expected outputs independently; a public request ID alone is
	// not sufficient authorization to sign the raw transaction returned by API.
	request, err := client.SafeReadMultisigRequests(ctx, funding.TraceId)
	var utxos []*mixin.SafeUtxo
	switch {
	case mixin.IsErrorCodes(err, mixin.EndpointNotFound):
		request = nil
		members := custodian.Members()
		sort.Strings(members)
		utxos, err = client.SafeListUtxos(ctx, mixin.SafeListUtxoOption{
			Members: members, Threshold: custodian.Threshold,
			Asset: funding.AssetId, State: mixin.SafeUtxoStateUnspent,
			Limit: 500, Order: "ASC",
		})
		if err == nil {
			utxos, err = selectFundingUTXOs(utxos, funding.Amount)
		}
	case err != nil:
		return nil, err
	default:
		utxos, err = funding.readMultisigInputs(ctx, client, request, custodian)
	}
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
	if request == nil {
		request, err = client.SafeCreateMultisigRequest(ctx, &mixin.SafeTransactionRequestInput{
			RequestID: funding.TraceId, RawTransaction: hex.EncodeToString(data),
		})
		if err != nil {
			return nil, err
		}
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

// SendMultisigTransactionMessage sends a per-participant approval card to the
// custodian conversation. The safe user only needs session credentials; its
// spend private key is neither read nor sent by this method.
func (funding *FundingRequest) SendMultisigTransactionMessage(ctx context.Context, request *mixin.SafeMultisigRequest, user *bot.SafeUser) error {
	conversationId, err := uuid.FromString(funding.ConversationId)
	if err != nil || conversationId == uuid.Nil || conversationId.String() != funding.ConversationId {
		return fmt.Errorf("invalid funding conversation id %s", funding.ConversationId)
	}
	custodian, err := mixin.MixAddressFromString(funding.CustodianAddress)
	if err != nil || custodian.Threshold <= 1 {
		return fmt.Errorf("invalid custodian address %s", funding.CustodianAddress)
	}
	if request == nil || request.RequestID != funding.TraceId || request.RevokedBy != "" {
		return fmt.Errorf("invalid custodian multisig request")
	}
	if request.SendersThreshold != custodian.Threshold || mixinnet.HashMembers(request.Senders) != mixinnet.HashMembers(custodian.Members()) {
		return fmt.Errorf("invalid custodian multisig members %s", request.RequestID)
	}
	if !slices.Contains(request.Senders, user.UserId) {
		return fmt.Errorf("observer %s is not a custodian member", user.UserId)
	}
	if !slices.Contains(request.Signers, user.UserId) {
		return fmt.Errorf("observer %s has not signed custodian multisig request %s", user.UserId, request.RequestID)
	}

	approveURL := fmt.Sprintf("https://mixin.one/multisigs/%s?action=sign", request.RequestID)
	revokeURL := fmt.Sprintf("https://mixin.one/multisigs/%s?action=unlock", request.RequestID)
	card := &bot.AppCardView{
		AppID: user.UserId,
		Title: "Custodian Transfer Approval",
		Description: fmt.Sprintf("Asset: %s\nAmount: %s\nFrom: %s\nTo: %s\nRequest ID: %s\nAction ID: %s\nSignatures: %d/%d",
			funding.AssetId,
			funding.Amount.String(),
			funding.CustodianAddress,
			funding.ReturnAddress,
			request.RequestID,
			funding.ActionId,
			len(request.Signers),
			request.SendersThreshold,
		),
		Actions: []bot.AppCardAction{
			{Label: "Approve", Action: approveURL, Color: "#42AD63"},
			{Label: "Revoke", Action: revokeURL, Color: "#DD4B65"},
		},
	}
	data, err := json.Marshal(card)
	if err != nil {
		return err
	}
	conversation, err := bot.ConversationShow(ctx, funding.ConversationId, user)
	if err != nil {
		return fmt.Errorf("read custodian conversation %s: %w", funding.ConversationId, err)
	}
	if conversation == nil || conversation.ConversationId != funding.ConversationId {
		return fmt.Errorf("invalid custodian conversation %s", funding.ConversationId)
	}

	participants := make(map[string]bool, len(conversation.Participants))
	for _, participant := range conversation.Participants {
		participants[participant.UserId] = true
	}
	for _, member := range request.Senders {
		if member != user.UserId && !participants[member] {
			return fmt.Errorf("custodian member %s is not in conversation %s", member, funding.ConversationId)
		}
	}

	payload := base64.RawURLEncoding.EncodeToString(data)
	messageSeed := UniqueId(funding.TraceId, fundingMultisigMessagePurpose)
	messages := make([]*bot.MessageRequest, 0, len(conversation.Participants))
	for _, participant := range conversation.Participants {
		if participant.UserId == user.UserId {
			continue
		}
		messages = append(messages, &bot.MessageRequest{
			ConversationId: conversation.ConversationId,
			RecipientId:    participant.UserId,
			MessageId:      UniqueId(messageSeed, participant.UserId),
			Category:       bot.MessageCategoryAppCard,
			DataBase64:     payload,
		})
	}
	if len(messages) == 0 {
		return fmt.Errorf("custodian conversation %s has no recipients", funding.ConversationId)
	}
	if err := bot.PostMessages(ctx, messages, user); err != nil {
		return fmt.Errorf("send custodian multisig request %s: %w", request.RequestID, err)
	}
	return nil
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

// Read inputs by identity, without filtering by their current spend state.
func (funding *FundingRequest) readMultisigInputs(ctx context.Context, client *mixin.Client, request *mixin.SafeMultisigRequest, custodian *mixin.MixAddress) ([]*mixin.SafeUtxo, error) {
	if request == nil || request.RequestID != funding.TraceId || request.RevokedBy != "" {
		return nil, fmt.Errorf("invalid custodian multisig request")
	}
	if request.AssetID != funding.AssetId {
		return nil, fmt.Errorf("funding request asset mismatch for %s", funding.TraceId)
	}
	transaction, err := mixinnet.TransactionFromRaw(request.RawTransaction)
	if err != nil {
		return nil, err
	}
	utxos := make([]*mixin.SafeUtxo, 0, len(transaction.Inputs))
	total := decimal.Zero
	for _, input := range transaction.Inputs {
		utxo, err := client.SafeReadUtxoByHash(ctx, *input.Hash, input.Index)
		if err != nil {
			return nil, err
		}
		total = total.Add(utxo.Amount)
		utxos = append(utxos, utxo)
	}
	if total.Cmp(funding.Amount) < 0 {
		return nil, fmt.Errorf("insufficient funding inputs %s < %s", total, funding.Amount)
	}
	return utxos, nil
}
