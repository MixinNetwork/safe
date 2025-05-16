package mtg

import (
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/util"
	"github.com/gofrs/uuid/v5"
)

func writeUuidLegacy(enc *common.Encoder, id string) {
	uid := uuid.FromStringOrNil(id)
	enc.WriteInt(16)
	enc.Write(uid.Bytes())
}

func writeStringLegacy(enc *common.Encoder, str string) {
	data := []byte(str)
	enc.WriteInt(len(data))
	enc.Write(data)
}

func writeBoolLegacy(enc *common.Encoder, f bool) {
	data := byte(0)
	if f {
		data = 1
	}
	err := enc.WriteByte(data)
	if err != nil {
		panic(err)
	}
}

func writeReferencesLegacy(enc *common.Encoder, refs []crypto.Hash) {
	rl := len(refs)
	enc.WriteInt(rl)
	for _, r := range refs {
		if !r.HasValue() {
			panic(fmt.Errorf("invalid ref %s", r.String()))
		}
		enc.Write(r[:])
	}
}

func writeConsumedLegacy(enc *common.Encoder, consumed []*UnifiedOutput, consumedIds []string) {
	if len(consumed) > 0 && len(consumed) != len(consumedIds) {
		panic(len(consumedIds))
	}
	cl := len(consumedIds)
	enc.WriteInt(cl)
	for _, id := range consumedIds {
		writeUuidLegacy(enc, id)
	}
}

func (tx *Transaction) SerializeLegacy() []byte {
	enc := common.NewEncoder()
	writeUuidLegacy(enc, tx.TraceId)
	writeUuidLegacy(enc, tx.AppId)
	writeUuidLegacy(enc, tx.OpponentAppId)
	enc.WriteInt(tx.State)
	writeUuidLegacy(enc, tx.AssetId)
	writeStringLegacy(enc, strings.Join(tx.Receivers, ","))
	enc.WriteInt(tx.Threshold)
	writeStringLegacy(enc, tx.Amount)
	writeStringLegacy(enc, tx.Memo)
	enc.WriteUint64(tx.Sequence)
	writeBoolLegacy(enc, tx.compaction)
	writeBoolLegacy(enc, tx.storage)
	writeReferencesLegacy(enc, tx.references)
	writeUuidLegacy(enc, tx.storageTraceId)
	writeConsumedLegacy(enc, tx.consumed, tx.consumedIds)
	return enc.Bytes()
}

func readUuidLegacy(dec *common.Decoder) (string, error) {
	data, err := dec.ReadBytes()
	if err != nil {
		return "", err
	}
	id, err := uuid.FromBytes(data)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func readStringLegacy(dec *common.Decoder) (string, error) {
	data, err := dec.ReadBytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func readBoolLegacy(dec *common.Decoder) (bool, error) {
	f, err := dec.ReadByte()
	if err != nil {
		return false, err
	}
	return f == 1, nil
}

func readReferencesLegacy(dec *common.Decoder) ([]crypto.Hash, error) {
	rl, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	var refs []crypto.Hash
	for ; rl > 0; rl -= 1 {
		var r crypto.Hash
		err := dec.Read(r[:])
		if err != nil {
			return nil, err
		}
		refs = append(refs, r)
	}
	return refs, nil
}

func readConsumedLegacy(dec *common.Decoder) ([]string, error) {
	cl, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	var outputs []string
	for ; cl > 0; cl -= 1 {
		oid, err := readUuidLegacy(dec)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, oid)
	}
	return outputs, nil
}

func DeserializeLegacy(rb []byte) (*Transaction, error) {
	dec := common.NewDecoder(rb)

	traceId, err := readUuidLegacy(dec)
	if err != nil {
		return nil, err
	}
	appId, err := readUuidLegacy(dec)
	if err != nil {
		return nil, err
	}
	opponentAppId, err := readUuidLegacy(dec)
	if err != nil {
		return nil, err
	}
	state, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	assetId, err := readUuidLegacy(dec)
	if err != nil {
		return nil, err
	}
	receivers, err := readStringLegacy(dec)
	if err != nil {
		return nil, err
	}
	treshold, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	amount, err := readStringLegacy(dec)
	if err != nil {
		return nil, err
	}
	memo, err := readStringLegacy(dec)
	if err != nil {
		return nil, err
	}
	sequence, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	compaction, err := readBoolLegacy(dec)
	if err != nil {
		return nil, err
	}
	storage, err := readBoolLegacy(dec)
	if err != nil {
		return nil, err
	}
	refs, err := readReferencesLegacy(dec)
	if err != nil {
		return nil, err
	}
	storageTraceId, err := readUuidLegacy(dec)
	if err != nil {
		return nil, err
	}
	ids, err := readConsumedLegacy(dec)
	if err != nil {
		return nil, err
	}

	tx := &Transaction{
		TraceId:       traceId,
		AppId:         appId,
		OpponentAppId: opponentAppId,
		State:         state,
		AssetId:       assetId,
		Receivers:     util.SplitIds(receivers, ","),
		Threshold:     treshold,
		Amount:        amount,
		Memo:          memo,
		Sequence:      sequence,
		compaction:    compaction,
		storage:       storage,
		references:    refs,
		consumedIds:   ids,
	}
	if storageTraceId != uuid.Nil.String() {
		tx.storageTraceId = storageTraceId
	}

	return tx, nil
}

func SerializeTransactionsLegacy(txs []*Transaction) []byte {
	enc := common.NewEncoder()
	enc.WriteInt(len(txs))
	for _, tx := range txs {
		b := tx.SerializeLegacy()
		enc.WriteInt(len(b))
		enc.Write(b)
	}
	return enc.Bytes()
}

func DeserializeTransactionsLegacy(tb []byte) ([]*Transaction, error) {
	dec := common.NewDecoder(tb)
	count, err := dec.ReadInt()
	if err != nil || count == 0 {
		return nil, err
	}
	txs := make([]*Transaction, count)
	for i := 0; i < count; i++ {
		b, err := dec.ReadBytes()
		if err != nil {
			return nil, err
		}
		tx, err := DeserializeLegacy(b)
		if err != nil {
			return nil, err
		}
		txs[i] = tx
	}
	return txs, nil
}
