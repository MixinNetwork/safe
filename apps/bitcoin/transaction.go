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
	"github.com/btcsuite/btcd/chaincfg"
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
	Hash      string
	Raw       []byte
	SigHashes []byte
	Fee       int64
}

func (raw *PartiallySignedTransaction) Marshal() []byte {
	enc := common.NewEncoder()
	hash, err := hex.DecodeString(raw.Hash)
	if err != nil || len(hash) != 32 {
		panic(raw.Hash)
	}
	writeBytes(enc, hash)
	writeBytes(enc, raw.Raw)
	writeBytes(enc, raw.SigHashes)
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
	sigHashes, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	fee, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	return &PartiallySignedTransaction{
		Hash:      hex.EncodeToString(hash),
		Raw:       raw,
		SigHashes: sigHashes,
		Fee:       int64(fee),
	}, nil
}

func (t *PartiallySignedTransaction) MsgTx() *wire.MsgTx {
	tx, _ := btcutil.NewTxFromBytes(t.Raw)
	return tx.MsgTx()
}

func BuildPartiallySignedTransaction(mainInputs []*Input, feeInputs []*Input, outputs []*Output, fvb int64) (*PartiallySignedTransaction, error) {
	msgTx := wire.NewMsgTx(2)

	mainAddress, mainSatoshi, err := addInputs(msgTx, mainInputs)
	if err != nil {
		return nil, fmt.Errorf("addInputs(main) => %v", err)
	}
	feeAddress, feeSatoshi, err := addInputs(msgTx, feeInputs)
	if err != nil {
		return nil, fmt.Errorf("addInputs(fee) => %v", err)
	}

	var outputSatoshi int64
	for _, out := range outputs {
		err := addOutput(msgTx, out.Address, out.Satoshi)
		if err != nil {
			return nil, fmt.Errorf("addOutput(%s, %d) => %v", out.Address, out.Satoshi, err)
		}
		outputSatoshi = outputSatoshi + out.Satoshi
	}
	if outputSatoshi > mainSatoshi {
		return nil, fmt.Errorf("insufficient input %d %d", mainSatoshi, outputSatoshi)
	}
	if change := mainSatoshi - outputSatoshi; change > 0 {
		err := addOutput(msgTx, mainAddress, change)
		if err != nil {
			return nil, fmt.Errorf("addOutput(%s, %d) => %v", mainAddress, change, err)
		}
	}

	estvb := (40 + len(msgTx.TxIn)*300 + (len(msgTx.TxOut)+1)*128) / 4
	feeConsumed := fvb * int64(estvb)
	if feeConsumed > feeSatoshi {
		return nil, buildInsufficientFeeError(feeSatoshi, feeConsumed)
	}
	if change := feeSatoshi - feeConsumed; change > 1000 {
		err := addOutput(msgTx, feeAddress, change)
		if err != nil {
			return nil, fmt.Errorf("addOutput(%s, %d) => %v", feeAddress, change, err)
		}
	} else {
		feeConsumed = feeSatoshi
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
	return &PartiallySignedTransaction{
		Hash:      msgTx.TxHash().String(),
		Raw:       rawBytes,
		SigHashes: sigHashes,
		Fee:       feeConsumed,
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

func addInputs(tx *wire.MsgTx, inputs []*Input) (string, int64, error) {
	var address string
	var inputSatoshi int64
	for _, input := range inputs {
		addr, err := addInput(tx, input)
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

func addInput(tx *wire.MsgTx, in *Input) (string, error) {
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
		wpkh, err := btcutil.NewAddressWitnessPubKeyHash(in.Script, &chaincfg.MainNetParams)
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
		mwsh, err := btcutil.NewAddressWitnessScriptHash(msh[:], &chaincfg.MainNetParams)
		if err != nil {
			return "", err
		}
		addr = mwsh.EncodeAddress()
		txIn.Sequence = MaxTransactionSequence
	case InputTypeP2WSHMultisigObserverSigner:
		msh := sha256.Sum256(in.Script)
		mwsh, err := btcutil.NewAddressWitnessScriptHash(msh[:], &chaincfg.MainNetParams)
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

func addOutput(tx *wire.MsgTx, address string, satoshi int64) error {
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	tx.AddTxOut(wire.NewTxOut(satoshi, script))
	return nil
}
