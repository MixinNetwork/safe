package bitcoin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
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
	*psbt.Packet
}

func (raw *PartiallySignedTransaction) Hash() string {
	return raw.UnsignedTx.TxHash().String()
}

func (raw *PartiallySignedTransaction) Marshal() []byte {
	var rawBuffer bytes.Buffer
	err := raw.Serialize(&rawBuffer)
	if err != nil {
		panic(err)
	}
	rb := rawBuffer.Bytes()
	_, err = psbt.NewFromRawBytes(bytes.NewReader(rb), false)
	if err != nil {
		panic(err)
	}
	return rb
}

func UnmarshalPartiallySignedTransaction(b []byte) (*PartiallySignedTransaction, error) {
	pkt, err := psbt.NewFromRawBytes(bytes.NewReader(b), false)
	if err != nil {
		return nil, err
	}
	return &PartiallySignedTransaction{
		Packet: pkt,
	}, nil
}

func (psbt *PartiallySignedTransaction) SigHash(idx int) []byte {
	tx := psbt.UnsignedTx
	pin := psbt.Inputs[idx]
	satoshi := pin.WitnessUtxo.Value
	pof := txscript.NewCannedPrevOutputFetcher(pin.WitnessScript, satoshi)
	tsh := txscript.NewTxSigHashes(tx, pof)
	hash, err := txscript.CalcWitnessSigHash(pin.WitnessScript, tsh, SigHashType, tx, idx, satoshi)
	if err != nil {
		panic(err)
	}
	sigHashes := psbt.Unknowns[0].Value
	if !bytes.Equal(hash, sigHashes[idx*32:idx*32+32]) {
		panic(idx)
	}
	return hash
}

func SpendSignedTransaction(raw string, feeInputs []*Input, accountant string, chain byte) (string, string, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return "", "", err
	}
	rtx, err := btcutil.NewTxFromBytes(b)
	if err != nil {
		return "", "", err
	}
	msgTx := rtx.MsgTx()
	mainCount := len(msgTx.TxIn)

	scripts := make([][]byte, len(feeInputs))
	for i := range feeInputs {
		scripts[i] = feeInputs[i].Script
	}
	_, _, err = addInputs(msgTx, feeInputs, chain)
	if err != nil {
		return "", "", fmt.Errorf("addInputs(fee) => %v", err)
	}
	b, err = hex.DecodeString(accountant)
	if err != nil {
		return "", "", err
	}
	privateKey, _ := btcec.PrivKeyFromBytes(b)

	for idx, in := range feeInputs {
		script := scripts[idx]
		idx = idx + mainCount
		pof := txscript.NewCannedPrevOutputFetcher(in.Script, in.Satoshi)
		tsh := txscript.NewTxSigHashes(msgTx, pof)
		hash, err := txscript.CalcWitnessSigHash(in.Script, tsh, txscript.SigHashAll, msgTx, idx, in.Satoshi)
		if err != nil {
			return "", "", err
		}
		signature := ecdsa.Sign(privateKey, hash)
		sig := append(signature.Serialize(), byte(txscript.SigHashAll))
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, script)
	}

	var signedBuffer bytes.Buffer
	err = msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	return msgTx.TxHash().String(), hex.EncodeToString(signedBuffer.Bytes()), err
}

func BuildPartiallySignedTransaction(mainInputs []*Input, outputs []*Output, rid []byte, chain byte) (*PartiallySignedTransaction, error) {
	msgTx := wire.NewMsgTx(2)

	mainAddress, mainSatoshi, err := addInputs(msgTx, mainInputs, chain)
	if err != nil {
		return nil, fmt.Errorf("addInputs(main) => %v", err)
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
	}

	estvb := (40 + len(msgTx.TxIn)*300 + (len(msgTx.TxOut)+1)*128) / 4
	if len(rid) > 0 && len(rid) <= 64 {
		estvb += len(rid)
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
	err = msgTx.BtcEncode(&rawBuffer, protocolVersion(chain), wire.BaseEncoding)
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

	sigHashes, err := calcSigHashes(msgTx, mainInputs)
	if err != nil {
		return nil, fmt.Errorf("calcSigHashes() => %v", err)
	}

	pkt, err := psbt.NewFromUnsignedTx(msgTx)
	if err != nil {
		return nil, fmt.Errorf("psbt.NewFromUnsignedTx() => %v", err)
	}
	for i, in := range mainInputs {
		address := mainAddress
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
		pin.SighashType = SigHashType
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
		hash, err := txscript.CalcWitnessSigHash(script, tsh, SigHashType, tx, i, satoshi)
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
