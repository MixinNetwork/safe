package observer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (node *Node) bitcoinAccountantSignTransaction(ctx context.Context, extra []byte) error {
	spsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(extra)

	tx, err := node.store.ReadTransactionApproval(ctx, spsbt.Hash)
	if err != nil || tx.State == common.RequestStateDone {
		return err
	}
	switch tx.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		panic(spsbt.Hash)
	}
	b := common.DecodeHexOrPanic(tx.RawTransaction)
	hpsbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)

	requests, err := node.keeperStore.ListAllSignaturesForTransaction(ctx, spsbt.Hash, common.RequestStateDone)
	if err != nil {
		return err
	}
	signed := make(map[int][]byte)
	for _, r := range requests {
		signed[r.InputIndex] = common.DecodeHexOrPanic(r.Signature.String)
	}

	msgTx := spsbt.Packet.UnsignedTx
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		hash := spsbt.SigHash(idx)
		utxo, _ := node.keeperStore.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if required {
			hpin := hpsbt.Packet.Inputs[idx]
			hsig := hpin.PartialSigs[0]
			if hex.EncodeToString(hsig.PubKey) != tx.Holder {
				panic(spsbt.Hash)
			}
			sig := append(hsig.Signature, byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{})
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)

			spin := spsbt.Packet.Inputs[idx]
			ssig := spin.PartialSigs[0]
			if hex.EncodeToString(ssig.PubKey) != tx.Signer {
				panic(spsbt.Hash)
			}
			if !bytes.Equal(ssig.Signature, signed[idx]) {
				panic(spsbt.Hash)
			}
			der, _ := ecdsa.ParseDERSignature(ssig.Signature)
			pub := common.DecodeHexOrPanic(tx.Signer)
			signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
			if !der.Verify(hash, signer.PubKey()) {
				panic(spsbt.Hash)
			}
			sig = append(ssig.Signature, byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{1})
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)

			hpsbt.Packet.Inputs[idx].PartialSigs = append(hpin.PartialSigs, spin.PartialSigs...)
		} else {
			accountant, err := node.bitcoinReadAccountantKey(ctx, tx.Accountant)
			if err != nil {
				return err
			}
			signature := ecdsa.Sign(accountant, hash)
			sig := append(signature.Serialize(), byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)

			hpsbt.Packet.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
				PubKey:    common.DecodeHexOrPanic(tx.Accountant),
				Signature: signature.Serialize(),
			}}
		}
	}

	var signedBuffer bytes.Buffer
	err = msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		panic(err)
	}

	raw := hex.EncodeToString(hpsbt.Marshal())
	err = node.store.FinishTransactionSignatures(ctx, spsbt.Hash, raw)
	logger.Printf("store.FinishTransactionSignatures(%s) => %v", spsbt.Hash, err)
	if err != nil {
		return err
	}
	return node.bitcoinBroadcastTransactionAndWriteDeposit(ctx, spsbt.Hash, signedBuffer.Bytes(), tx.Chain)
}

func (node *Node) bitcoinBroadcastTransactionAndWriteDeposit(ctx context.Context, hash string, raw []byte, chain byte) error {
	rpc, _ := node.bitcoinParams(chain)
	err := node.bitcoinBroadcastTransaction(hash, raw, chain)
	if err != nil {
		return fmt.Errorf("node.bitcoinBroadcastTransaction(%s, %x) => %v", hash, raw, err)
	}
	tx, err := bitcoin.RPCGetTransaction(chain, rpc, hash)
	if err != nil || tx == nil {
		return fmt.Errorf("bitcoin.RPCGetTransaction(%s) => %v %v", hash, tx, err)
	}
	return node.bitcoinProcessTransaction(ctx, tx, chain)
}

func (node *Node) bitcoinBroadcastTransaction(hash string, raw []byte, chain byte) error {
	rpc, _ := node.bitcoinParams(chain)
	id, err := bitcoin.RPCSendRawTransaction(rpc, hex.EncodeToString(raw))
	if err != nil {
		return err
	}
	if id != hash {
		return fmt.Errorf("malformed bitcoin transaction %s %s", hash, id)
	}
	return nil
}
