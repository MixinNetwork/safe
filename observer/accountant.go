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
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (node *Node) bitcoinAccountantSignTransaction(ctx context.Context, extra []byte) error {
	transactionHash := hex.EncodeToString(extra[:32])
	bundle := common.DecodeIndexedBytesSorted(extra[32:])

	tx, err := node.store.ReadTransactionApproval(ctx, transactionHash)
	if err != nil {
		return err
	}
	if tx.Chain != keeper.SafeChainBitcoin {
		panic(transactionHash)
	}

	requests, err := node.keeperStore.ListAllSignaturesForTransaction(ctx, transactionHash, common.RequestStateDone)
	if err != nil {
		return err
	}
	signed := make(map[int][]byte)
	for _, r := range requests {
		signed[r.OutputIndex] = common.DecodeHexOrPanic(r.Signature.String)
	}
	if len(signed) != len(bundle) {
		panic(transactionHash)
	}
	for _, bs := range bundle {
		if !bytes.Equal(signed[bs.Index], bs.Data) {
			panic(transactionHash)
		}
	}

	b := common.DecodeHexOrPanic(tx.RawTransaction)
	psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(b)
	msgTx := psbt.MsgTx()
	for idx := range msgTx.TxIn {
		pop := msgTx.TxIn[idx].PreviousOutPoint
		hash := psbt.SigHashes[idx*32 : idx*32+32]
		utxo, _ := node.keeperStore.ReadBitcoinUTXO(ctx, pop.Hash.String(), int(pop.Index))
		required := node.checkBitcoinUTXOSignatureRequired(ctx, pop)
		if required {
			sig := tx.Partials[idx]
			if len(sig) < 32 {
				panic(transactionHash)
			}
			sig = append(sig, byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{})
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)

			sig = signed[idx]
			if len(sig) < 32 {
				panic(transactionHash)
			}
			der, _ := ecdsa.ParseDERSignature(sig)
			pub := common.DecodeHexOrPanic(tx.Signer)
			signer, _ := btcutil.NewAddressPubKey(pub, &chaincfg.MainNetParams)
			if !der.Verify(hash, signer.PubKey()) {
				panic(transactionHash)
			}
			sig = append(sig, byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, []byte{1})

			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)
		} else {
			accountant, err := node.bitcoinReadAccountantKey(ctx, tx.Accountant)
			if err != nil {
				return err
			}
			signature := ecdsa.Sign(accountant, hash)
			sig := append(signature.Serialize(), byte(txscript.SigHashAll))
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
			msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, utxo.Script)
		}
	}

	var signedBuffer bytes.Buffer
	err = msgTx.BtcEncode(&signedBuffer, wire.ProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		panic(err)
	}
	psbt.Raw = signedBuffer.Bytes()

	err = node.store.FinishTransactionSignatures(ctx, transactionHash, hex.EncodeToString(psbt.Marshal()))
	logger.Printf("store.FinishTransactionSignatures(%s) => %v", transactionHash, err)
	if err != nil {
		return err
	}

	return node.bitcoinBroadcastTransaction(transactionHash, psbt.Raw)
}

func (node *Node) bitcoinBroadcastTransaction(hash string, raw []byte) error {
	id, err := bitcoin.RPCSendRawTransaction(node.conf.BitcoinRPC, hex.EncodeToString(raw))
	if err != nil {
		return err
	}
	if id != hash {
		return fmt.Errorf("malformed bitcoin transaction %s %s", hash, id)
	}
	return nil
}
