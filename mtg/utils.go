package mtg

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/util"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

func UniqueId(a, b string) string {
	return util.UniqueId(a, b)
}

func CheckRetryableError(err error) bool {
	if err == nil {
		return false
	}
	es := err.Error()
	switch {
	case strings.Contains(es, "EOF"):
	case strings.Contains(es, "context deadline exceeded"):
	case strings.Contains(es, "connection reset by peer"):
	case strings.Contains(es, "Client.Timeout exceeded"):
	case strings.Contains(es, "Bad Gateway"):
	case strings.Contains(es, "Internal Server Error"):
	case strings.Contains(es, "invalid character '<' looking for beginning of value"):
	case strings.Contains(es, "TLS handshake timeout"):
	default:
		return false
	}
	return true
}

func NewMixAddress(ctx context.Context, members []string, threshold byte) (*mixin.MixAddress, bool, error) {
	if len(members) == 0 || threshold == 0 {
		panic(len(members))
	}
	if util.CheckTestEnvironment(ctx) {
		for i, m := range members {
			_, err := mixinnet.AddressFromString(m)
			if err == nil {
				break
			}
			members[i] = UniqueId(m, m)
		}
	}

	isUuidMembers := false
	ma, err := mixin.NewMainnetMixAddress(members, 1)
	if err != nil {
		ma, err = mixin.NewMixAddress(members, 1)
		if err != nil {
			return nil, false, err
		}
		isUuidMembers = true
	}
	ma.Threshold = threshold
	return ma, isUuidMembers, nil
}

func DecodeMixinExtraHEX(memo string) (string, []byte) {
	extra, err := hex.DecodeString(memo)
	if err != nil {
		return "", nil
	}
	return DecodeMixinExtraBase64(string(extra))
}

func DecodeMixinExtraBase64(extra string) (string, []byte) {
	data, err := base64.RawURLEncoding.DecodeString(extra)
	if err != nil || len(data) < 16 {
		return "", nil
	}
	aid := uuid.FromBytesOrNil(data[0:16])
	return aid.String(), data[16:]
}

func EncodeMixinExtraBase64(appId string, extra []byte) string {
	gid, err := uuid.FromString(appId)
	if err != nil {
		panic(err)
	}
	data := gid.Bytes()
	data = append(data, extra...)
	s := base64.RawURLEncoding.EncodeToString(data)
	return s
}

func newCommonOutput(out *mixinnet.Output) *common.Output {
	cout := &common.Output{
		Type:   common.OutputTypeScript,
		Amount: common.NewIntegerFromString(out.Amount.String()),
		Script: common.Script(out.Script),
		Mask:   crypto.Key(out.Mask),
	}
	for _, k := range out.Keys {
		ck := crypto.Key(k)
		cout.Keys = append(cout.Keys, &ck)
	}
	return cout
}

func (grp *Group) getSpendPublicKeyUntilSufficient(ctx context.Context) (string, error) {
	for {
		me, err := grp.mixin.UserMe(ctx)
		logger.Verbosef("Group.UserMe() => %v\n", err)
		if CheckRetryableError(err) {
			time.Sleep(3 * time.Second)
			continue
		}
		return me.SpendPublicKey, err
	}
}

func (grp *Group) ReadKernelTransactionUntilSufficient(ctx context.Context, txHash string) (*common.VersionedTransaction, error) {
	key := fmt.Sprintf("readKernelTransactionUntilSufficient(%s)", txHash)
	val, err := grp.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}
	if val != "" {
		b, err := base64.RawURLEncoding.DecodeString(val)
		if err != nil {
			panic(err)
		}
		ver, err := common.UnmarshalVersionedTransaction(b)
		if err != nil {
			panic(err)
		}
		return ver, nil
	}
	ver, err := grp.readKernelTransactionUntilSufficientImpl(ctx, txHash)
	if err != nil {
		return nil, err
	}
	val = base64.RawURLEncoding.EncodeToString(ver.Marshal())
	err = grp.store.WriteCache(ctx, key, val)
	if err != nil {
		panic(err)
	}
	return ver, nil
}

func (grp *Group) readKernelTransactionUntilSufficientImpl(ctx context.Context, txHash string) (*common.VersionedTransaction, error) {
	if util.CheckTestEnvironment(ctx) {
		hash, err := crypto.HashFromString(txHash)
		if err != nil {
			return nil, err
		}
		tx, err := grp.store.ReadTransactionByHash(ctx, hash)
		if err != nil {
			return nil, err
		}
		if tx == nil {
			ver := common.NewTransactionV5(common.XINAssetId).AsVersioned()
			return ver, nil
		}
		ver, err := common.UnmarshalVersionedTransaction(tx.Raw)
		return ver, err
	}
	for {
		ver, snapshot, err := GetKernelTransaction(grp.kernelRPC, txHash)
		if CheckRetryableError(err) || snapshot == "" {
			time.Sleep(time.Second)
			continue
		}
		return ver, err
	}
}

func (grp *Group) readTransactionUntilSufficient(ctx context.Context, id string) (*SafeTransactionRequest, error) {
	key := fmt.Sprintf("readTransactionUntilSufficient(%s)", id)
	val, err := grp.store.ReadCache(ctx, key)
	if err != nil {
		panic(err)
	}
	if val != "" {
		var r SafeTransactionRequest
		err = json.Unmarshal([]byte(val), &r)
		if err != nil {
			panic(err)
		}
		return &r, nil
	}
	r, err := grp.readTransactionUntilSufficientImpl(ctx, id)
	if err != nil || r == nil || r.State != SafeUtxoStateSpent {
		return r, err
	}
	if rr := r.Receivers[0]; rr != nil && rr.Destination != "" && rr.WithdrawalHash == "" {
		return r, nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	err = grp.store.WriteCache(ctx, key, string(b))
	if err != nil {
		panic(err)
	}
	return r, nil
}

type SafeTransactionReceiver struct {
	Members        []string `json:"members"`
	MemberHash     string   `json:"members_hash"`
	Threshold      uint8    `json:"threshold"`
	Destination    string   `json:"destination"`
	Tag            string   `json:"tag"`
	WithdrawalHash string   `json:"withdrawal_hash"`
}

type SafeTransactionRequest struct {
	RequestID        string                     `json:"request_id"`
	TransactionHash  string                     `json:"transaction_hash"`
	UserID           string                     `json:"user_id"`
	KernelAssetID    mixinnet.Hash              `json:"kernel_asset_id"`
	AssetID          mixinnet.Hash              `json:"asset_id"`
	Amount           decimal.Decimal            `json:"amount"`
	CreatedAt        time.Time                  `json:"created_at"`
	UpdatedAt        time.Time                  `json:"updated_at"`
	Extra            string                     `json:"extra"`
	Receivers        []*SafeTransactionReceiver `json:"receivers"`
	Senders          []string                   `json:"senders"`
	SendersHash      string                     `json:"senders_hash"`
	SendersThreshold uint8                      `json:"senders_threshold"`
	Signers          []string                   `json:"signers"`
	SnapshotHash     string                     `json:"snapshot_hash"`
	SnapshotAt       *time.Time                 `json:"snapshot_at"`
	State            SafeUtxoState              `json:"state"`
	RawTransaction   string                     `json:"raw_transaction"`
	Views            []mixinnet.Key             `json:"views"`
	RevokedBy        string                     `json:"revoked_by"`

	Asset mixinnet.Hash `json:"asset"`
}

func (grp *Group) readTransactionUntilSufficientImpl(ctx context.Context, id string) (*SafeTransactionRequest, error) {
	if util.CheckTestEnvironment(ctx) {
		tx, err := grp.store.ReadTransactionByTraceId(ctx, id)
		if err != nil {
			return nil, err
		}
		return &SafeTransactionRequest{
			RequestID:       tx.TraceId,
			RawTransaction:  hex.EncodeToString(tx.Raw),
			TransactionHash: tx.Hash.String(),
			Signers:         []string{grp.GroupId},
		}, nil
	}
	for {
		var req SafeTransactionRequest
		err := grp.mixin.Get(ctx, "/safe/transactions/"+id, nil, &req)
		logger.Verbosef("Group.SafeReadTransactionRequest(%s) => %v %v\n", id, req, err)
		if err == nil {
			return &req, nil
		}
		if CheckRetryableError(err) {
			time.Sleep(time.Second)
			continue
		}
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
}

func (grp *Group) getTransactionInputsAndRecipients(ctx context.Context, tx *Transaction, outputs []*UnifiedOutput) ([]*UnifiedOutput, []*TransactionRecipient, error) {
	var tr []*TransactionRecipient
	if tx.IsWithdrawal() {
		tr = []*TransactionRecipient{{
			Amount:      tx.Amount,
			Destination: tx.Destination.String,
		}}
		if tx.Tag.Valid {
			tr[0].Tag = tx.Tag.String
		}
	} else {
		ma, uuidMember, err := NewMixAddress(ctx, tx.Receivers, byte(tx.Threshold))
		if err != nil {
			return nil, nil, err
		}
		tr = []*TransactionRecipient{{
			MixAddress: ma,
			Amount:     tx.Amount,
			UuidMember: uuidMember,
		}}
	}

	target := common.NewIntegerFromString(tx.Amount)
	var total common.Integer
	var consumed []*UnifiedOutput
	for _, out := range outputs {
		total = total.Add(common.NewIntegerFromString(out.Amount.String()))
		consumed = append(consumed, out)
		if total.Cmp(target) >= 0 && len(consumed) >= grp.groupSize {
			break
		}
	}

	change := total.Sub(target)
	if change.Sign() < 0 {
		return nil, nil, fmt.Errorf("insufficient %d %s %s", len(outputs), total, tx.Amount)
	} else if change.Sign() > 0 {
		ma, uuidMember, err := NewMixAddress(ctx, grp.GetMembers(), byte(grp.GetThreshold()))
		if err != nil {
			return nil, nil, err
		}
		tr = append(tr, &TransactionRecipient{
			MixAddress: ma,
			Amount:     change.String(),
			UuidMember: uuidMember,
		})
	}
	return consumed, tr, nil
}

func (grp *Group) createGhostKeysUntilSufficient(ctx context.Context, tx *Transaction, tr []*TransactionRecipient) (map[int]*mixin.GhostKeys, error) {
	gkm := make(map[int]*mixin.GhostKeys, len(tr))
	if util.CheckTestEnvironment(ctx) {
		if tx.TraceId == "cf0564ba-bf51-4e8c-b504-3beb6c5c65e3" {
			tr[1].MixAddress.Threshold = 2
			mask, _ := mixinnet.KeyFromString("f18e0e276648b1d42063f8bcf9d5a57252f4048c9939ded0999a0e263716976e")
			key1, _ := mixinnet.KeyFromString("f5c8b3dbb7a5b2f7e1e4640d9f61c142cda547917f227ba21ebc5d554651c50d")
			key2, _ := mixinnet.KeyFromString("18f71fbe1b5055f3d882a4ae2813fad315bf0dcb5a0e60f091121db882baff77")
			gkm[1] = &mixin.GhostKeys{
				Mask: mask,
				Keys: []mixinnet.Key{key1, key2},
			}
			return gkm, nil
		}
		key1, err := testGetGhostKeys(tx, 0)
		if err != nil {
			return nil, err
		}
		key2, err := testGetGhostKeys(tx, 1)
		if err != nil {
			return nil, err
		}
		gkm[0] = key1
		gkm[1] = key2
		return gkm, nil
	}

	var uuidGkrs []*mixin.GhostInput
	for i, r := range tr {
		if r.MixAddress == nil {
			continue
		}
		members := r.MixAddress.Members()
		if r.UuidMember {
			sort.Strings(members)
			hint := UniqueId(tx.TraceId, fmt.Sprintf("index:%d", i))
			uuidGkrs = append(uuidGkrs, &mixin.GhostInput{
				Receivers: members,
				Index:     uint8(i),
				Hint:      hint,
			})
		} else {
			index := make([]byte, 16)
			binary.BigEndian.PutUint16(index, uint16(i))

			seed := uuid.FromStringOrNil(tx.TraceId).Bytes()
			seed = append(seed, uuid.FromStringOrNil(tx.AssetId).Bytes()...)
			seed = append(seed, uuid.FromStringOrNil(tx.OpponentAppId).Bytes()...)
			seed = append(seed, index...)
			r := mixinnet.KeyFromBytes(seed)

			keys := make([]mixinnet.Key, len(members))
			for i, a := range members {
				addr, err := mixinnet.AddressFromString(a)
				if err != nil {
					return nil, err
				}
				key := mixinnet.DeriveGhostPublicKey(mixinnet.TxVersionHashSignature, &r, &addr.PublicViewKey, &addr.PublicSpendKey, uint8(i))
				keys[i] = *key
			}
			gkm[i] = &mixin.GhostKeys{
				Mask: r.Public(),
				Keys: keys,
			}
		}
	}
	if len(uuidGkrs) == 0 {
		return gkm, nil
	}

	for {
		keys, err := grp.mixin.SafeCreateGhostKeys(ctx, uuidGkrs, grp.GetMembers()...)
		logger.Verbosef("Group.SafeCreateGhostKeys(%s) => %v %v\n", tx.TraceId, keys, err)
		if CheckRetryableError(err) {
			time.Sleep(3 * time.Second)
			continue
		}
		for i, g := range keys {
			index := uuidGkrs[i].Index
			gkm[int(index)] = g
		}
		return gkm, err
	}
}

func testGetGhostKeys(tx *Transaction, index int) (*mixin.GhostKeys, error) {
	k := &mixin.GhostKeys{}
	for _, r := range tx.Receivers {
		id := UniqueId(r, tx.TraceId)
		id = UniqueId(id, fmt.Sprint(index))
		bs := uuid.FromStringOrNil(id).Bytes()
		bs = append(bs, bs...)
		key, err := mixinnet.KeyFromSeed(hex.EncodeToString(bs))
		if err != nil {
			return nil, err
		}
		k.Keys = append(k.Keys, key)
	}

	id := UniqueId(tx.TraceId, fmt.Sprint(index))
	bs := uuid.FromStringOrNil(id).Bytes()
	bs = append(bs, bs...)
	m, err := mixinnet.KeyFromSeed(hex.EncodeToString(bs))
	if err != nil {
		return nil, err
	}
	k.Mask = m
	return k, nil
}
