package bitcoin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type Input struct {
	TransactionHash string
	Index           uint32
	Satoshi         int64
	Script          []byte
	Sequence        uint32
	RouteBackup     bool
}

type Output struct {
	Address  string
	Satoshi  int64
	Height   uint64
	Coinbase bool
}

type PartiallySignedTransaction struct {
	Hash   string
	Fee    int64
	Packet *psbt.Packet
}

func (raw *PartiallySignedTransaction) Marshal() []byte {
	enc := common.NewEncoder()
	hash, err := hex.DecodeString(raw.Hash)
	if err != nil || len(hash) != 32 {
		panic(raw.Hash)
	}

	var rawBuffer bytes.Buffer
	err = raw.Packet.Serialize(&rawBuffer)
	if err != nil {
		panic(err)
	}
	rb := rawBuffer.Bytes()
	_, err = psbt.NewFromRawBytes(bytes.NewReader(rb), false)
	if err != nil {
		panic(err)
	}

	writeBytes(enc, hash)
	writeBytes(enc, rb)
	enc.WriteUint64(uint64(raw.Fee))
	return enc.Bytes()
}

func UnmarshalPartiallySignedTransaction(b []byte) (*PartiallySignedTransaction, error) {
	dec := common.NewDecoder(b)
	hash, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	raw, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	fee, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		return nil, err
	}
	pfee, err := pkt.GetTxFee()
	if err != nil {
		return nil, err
	}
	if uint64(pfee) != fee {
		return nil, fmt.Errorf("fee %d %d", fee, pfee)
	}
	if hex.EncodeToString(hash) != pkt.UnsignedTx.TxHash().String() {
		return nil, fmt.Errorf("hash %x %s", hash, pkt.UnsignedTx.TxHash().String())
	}
	return &PartiallySignedTransaction{
		Hash:   hex.EncodeToString(hash),
		Fee:    int64(fee),
		Packet: pkt,
	}, nil
}

func (t *PartiallySignedTransaction) SigHash(idx int) []byte {
	psbt := t.Packet
	tx := psbt.UnsignedTx
	pin := psbt.Inputs[idx]
	satoshi := pin.WitnessUtxo.Value
	pof := txscript.NewCannedPrevOutputFetcher(pin.WitnessScript, satoshi)
	tsh := txscript.NewTxSigHashes(tx, pof)
	hash, err := txscript.CalcWitnessSigHash(pin.WitnessScript, tsh, txscript.SigHashAll, tx, idx, satoshi)
	if err != nil {
		panic(err)
	}
	sigHashes := psbt.Unknowns[0].Value
	if !bytes.Equal(hash, sigHashes[idx*32:idx*32+32]) {
		panic(idx)
	}
	return hash
}

func BuildPartiallySignedTransaction(mainInputs []*Input, feeInputs []*Input, outputs []*Output, fvb int64, rid []byte, chain byte) (*PartiallySignedTransaction, error) {
	msgTx := wire.NewMsgTx(2)

	mainAddress, mainSatoshi, err := addInputs(msgTx, mainInputs, chain)
	if err != nil {
		return nil, fmt.Errorf("addInputs(main) => %v", err)
	}
	feeAddress, feeSatoshi, err := addInputs(msgTx, feeInputs, chain)
	if err != nil {
		return nil, fmt.Errorf("addInputs(fee) => %v", err)
	}

	var outputSatoshi int64
	for _, out := range outputs {
		added, err := addOutput(msgTx, out.Address, out.Satoshi, chain)
		if err != nil || !added {
			return nil, fmt.Errorf("addOutput(%s, %d) => %t %v", out.Address, out.Satoshi, added, err)
		}
		outputSatoshi = outputSatoshi + out.Satoshi
	}
	if outputSatoshi > mainSatoshi {
		return nil, buildInsufficientInputError("main", mainSatoshi, outputSatoshi)
	}
	mainChange := mainSatoshi - outputSatoshi
	if mainChange > ValueDust {
		added, err := addOutput(msgTx, mainAddress, mainChange, chain)
		if err != nil || !added {
			return nil, fmt.Errorf("addOutput(%s, %d) => %t %v", mainAddress, mainChange, added, err)
		}
	} else {
		feeSatoshi = feeSatoshi + mainChange
	}

	estvb := (40 + len(msgTx.TxIn)*300 + (len(msgTx.TxOut)+1)*128) / 4
	if len(rid) > 0 && len(rid) <= 64 {
		estvb += len(rid)
	}

	feeConsumed := fvb * int64(estvb)
	if feeConsumed > feeSatoshi {
		return nil, buildInsufficientInputError("fee", feeSatoshi, feeConsumed)
	}
	feeChange := feeSatoshi - feeConsumed
	if feeChange > ValueDust {
		added, err := addOutput(msgTx, feeAddress, feeChange, chain)
		if err != nil || !added {
			return nil, fmt.Errorf("addOutput(%s, %d) => %t %v", feeAddress, feeChange, added, err)
		}
	} else {
		feeConsumed = feeSatoshi
	}

	if len(rid) > 0 && len(rid) <= 64 {
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_RETURN)
		builder.AddData(rid)
		script, err := builder.Script()
		if err != nil {
			return nil, fmt.Errorf("return(%x) => %v", rid, err)
		}
		msgTx.AddTxOut(wire.NewTxOut(0, script))
	}

	var rawBuffer bytes.Buffer
	err = msgTx.BtcEncode(&rawBuffer, wire.ProtocolVersion, wire.BaseEncoding)
	if err != nil {
		return nil, fmt.Errorf("BtcEncode() => %v", err)
	}
	rawBytes := rawBuffer.Bytes()
	if len(rawBytes) > estvb {
		return nil, fmt.Errorf("estimation %d %d", len(rawBytes), estvb)
	}
	if estvb*4 > MaxStandardTxWeight {
		return nil, fmt.Errorf("large %d", estvb)
	}

	tx := btcutil.NewTx(msgTx)
	err = blockchain.CheckTransactionSanity(tx)
	if err != nil {
		return nil, fmt.Errorf("blockchain.CheckTransactionSanity() => %v", err)
	}
	lockTime := time.Now().Add(TimeLockMaximum)
	err = mempool.CheckTransactionStandard(tx, txscript.LockTimeThreshold, lockTime, mempool.DefaultMinRelayTxFee, 2)
	if err != nil {
		return nil, fmt.Errorf("mempool.CheckTransactionStandard() => %v", err)
	}

	allInputs := append(mainInputs, feeInputs...)
	sigHashes, err := calcSigHashes(msgTx, allInputs)
	if err != nil {
		return nil, fmt.Errorf("calcSigHashes() => %v", err)
	}

	pkt, err := psbt.NewFromUnsignedTx(msgTx)
	if err != nil {
		return nil, fmt.Errorf("psbt.NewFromUnsignedTx() => %v", err)
	}
	for i, in := range allInputs {
		address := mainAddress
		if i >= len(mainInputs) {
			address = feeAddress
		}
		addr, err := btcutil.DecodeAddress(address, netConfig(chain))
		if err != nil {
			panic(address)
		}
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			panic(address)
		}
		pin := psbt.NewPsbtInput(nil, &wire.TxOut{
			Value:    in.Satoshi,
			PkScript: pkScript,
		})
		pin.WitnessScript = in.Script
		pin.SighashType = txscript.SigHashAll
		if !pin.IsSane() {
			panic(address)
		}
		pkt.Inputs[i] = *pin
	}
	pkt.Unknowns = []*psbt.Unknown{{Key: []byte("SIGHASHES"), Value: sigHashes}}
	err = pkt.SanityCheck()
	if err != nil {
		return nil, fmt.Errorf("psbt.SanityCheck() => %v", err)
	}

	return &PartiallySignedTransaction{
		Hash:   msgTx.TxHash().String(),
		Fee:    feeConsumed,
		Packet: pkt,
	}, nil
}

func calcSigHashes(tx *wire.MsgTx, inputs []*Input) ([]byte, error) {
	var hashes []byte
	for i := range tx.TxIn {
		if inputs[i].TransactionHash != tx.TxIn[i].PreviousOutPoint.Hash.String() {
			panic(tx.TxHash().String())
		}
		if inputs[i].Index != tx.TxIn[i].PreviousOutPoint.Index {
			panic(tx.TxHash().String())
		}
		script, satoshi := inputs[i].Script, inputs[i].Satoshi
		pof := txscript.NewCannedPrevOutputFetcher(script, satoshi)
		tsh := txscript.NewTxSigHashes(tx, pof)
		hash, err := txscript.CalcWitnessSigHash(script, tsh, txscript.SigHashAll, tx, i, satoshi)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash...)
	}
	return hashes, nil
}

func addInputs(tx *wire.MsgTx, inputs []*Input, chain byte) (string, int64, error) {
	var address string
	var inputSatoshi int64
	for _, input := range inputs {
		addr, err := addInput(tx, input, chain)
		if err != nil {
			return "", 0, err
		}
		if address == "" {
			address = addr
		}
		if address != addr {
			return "", 0, fmt.Errorf("input address %s %s", address, addr)
		}
		inputSatoshi = inputSatoshi + input.Satoshi
	}
	return address, inputSatoshi, nil
}

func addInput(tx *wire.MsgTx, in *Input, chain byte) (string, error) {
	var addr string
	hash, err := chainhash.NewHashFromStr(in.TransactionHash)
	if err != nil {
		return "", err
	}
	txIn := &wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  *hash,
			Index: in.Index,
		},
	}
	typ := checkScriptType(in.Script)
	if in.RouteBackup {
		typ = InputTypeP2WSHMultisigObserverSigner
	}
	switch typ {
	case InputTypeP2WPKHAccoutant:
		in.Script = btcutil.Hash160(in.Script)
		wpkh, err := btcutil.NewAddressWitnessPubKeyHash(in.Script, netConfig(chain))
		if err != nil {
			return "", err
		}
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0)
		builder.AddData(in.Script)
		script, err := builder.Script()
		if err != nil {
			return "", err
		}
		in.Script = script
		addr = wpkh.EncodeAddress()
		txIn.Sequence = MaxTransactionSequence
	case InputTypeP2WSHMultisigHolderSigner:
		msh := sha256.Sum256(in.Script)
		mwsh, err := btcutil.NewAddressWitnessScriptHash(msh[:], netConfig(chain))
		if err != nil {
			return "", err
		}
		addr = mwsh.EncodeAddress()
		txIn.Sequence = MaxTransactionSequence
	case InputTypeP2WSHMultisigObserverSigner:
		msh := sha256.Sum256(in.Script)
		mwsh, err := btcutil.NewAddressWitnessScriptHash(msh[:], netConfig(chain))
		if err != nil {
			return "", err
		}
		addr = mwsh.EncodeAddress()
		txIn.Sequence = in.Sequence
	default:
		return "", fmt.Errorf("invalid input type %d", typ)
	}
	if txIn.Sequence == 0 {
		return "", fmt.Errorf("invalid sequence %d", in.Sequence)
	}
	tx.AddTxIn(txIn)
	return addr, nil
}

func addOutput(tx *wire.MsgTx, address string, satoshi int64, chain byte) (bool, error) {
	addr, err := btcutil.DecodeAddress(address, netConfig(chain))
	if err != nil {
		return false, err
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return false, err
	}
	out := wire.NewTxOut(satoshi, script)
	if out.Value > 0 && mempool.IsDust(out, mempool.DefaultMinRelayTxFee) {
		return false, nil
	}
	tx.AddTxOut(out)
	return true, nil
}
