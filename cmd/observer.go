package cmd

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/observer"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/urfave/cli/v2"
)

func ObserverBootCmd(c *cli.Context) error {
	logger.SetLevel(logger.VERBOSE)
	ctx := context.Background()

	ua := fmt.Sprintf("Mixin Safe Observer (%s)", config.AppVersion)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}

	db, err := observer.OpenSQLite3Store(mc.Observer.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	kd, err := keeper.OpenSQLite3ReadOnlyStore(mc.Observer.KeeperStoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()

	mixin, err := mixin.NewFromKeystore(&mixin.Keystore{
		ClientID:   mc.Observer.App.ClientId,
		SessionID:  mc.Observer.App.SessionId,
		PrivateKey: mc.Observer.App.PrivateKey,
		PinToken:   mc.Observer.App.PinToken,
	})
	if err != nil {
		return err
	}

	node := observer.NewNode(db, kd, mc.Observer, mc.Keeper.MTG, mixin)
	go node.StartHTTP(c.App.Metadata["README"].(string))
	node.Boot(ctx)
	return nil
}

func ObserverFillAccountants(c *cli.Context) error {
	ctx := context.Background()
	chain := byte(c.Int("chain"))
	switch chain {
	case bitcoin.ChainBitcoin:
	case bitcoin.ChainLitecoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}
	satoshi, count := c.Int64("satoshi"), c.Int64("count")
	if satoshi <= 0 || count <= 0 {
		return fmt.Errorf("invalid satoshi %d or count %d", satoshi, count)
	}

	fee := c.Int64("fee") * int64(320+(count+1)*128) / 4
	if fee <= 0 || (satoshi-fee)/count < 5000 {
		return fmt.Errorf("invalid fee %d", c.Int64("fee"))
	}
	amount := (satoshi - fee) / count
	fee = satoshi - amount*count

	kb, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return fmt.Errorf("invalid private key hex %s", c.String("key"))
	}
	priv, pub := btcec.PrivKeyFromBytes(kb)

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}
	db, err := observer.OpenSQLite3Store(mc.Observer.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	input := strings.Split(c.String("input"), ":")[0]
	index, _ := strconv.ParseInt(strings.Split(c.String("input"), ":")[1], 10, 64)
	inputs := []*bitcoin.Input{{
		TransactionHash: input,
		Index:           uint32(index),
		Satoshi:         satoshi,
		Script:          pub.SerializeCompressed(),
		Sequence:        bitcoin.MaxTransactionSequence,
	}}

	keys := make(map[string]*btcec.PrivateKey)
	outputs := make([]*bitcoin.Output, count)
	for i := range outputs {
		priv, addr, err := generateAccountantKey(chain)
		if err != nil {
			return err
		}
		outputs[i] = &bitcoin.Output{
			Address: addr,
			Satoshi: amount,
		}
		keys[addr] = priv
	}

	pst, err := bitcoin.BuildPartiallySignedTransaction(inputs, outputs, nil, chain)
	if err != nil {
		return err
	}
	msgTx := pst.UnsignedTx
	if int64(len(msgTx.TxOut)) != count+1 {
		return fmt.Errorf("invalid outputs %d", len(msgTx.TxOut))
	}
	msgTx.TxOut = msgTx.TxOut[:count]

	for idx := range msgTx.TxIn {
		in := inputs[idx]
		pof := txscript.NewCannedPrevOutputFetcher(in.Script, in.Satoshi)
		tsh := txscript.NewTxSigHashes(msgTx, pof)
		hash, err := txscript.CalcWitnessSigHash(in.Script, tsh, txscript.SigHashAll, msgTx, idx, in.Satoshi)
		if err != nil {
			return err
		}
		signature := ecdsa.Sign(priv, hash)
		sig := append(signature.Serialize(), byte(txscript.SigHashAll))
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, sig)
		msgTx.TxIn[idx].Witness = append(msgTx.TxIn[idx].Witness, pub.SerializeCompressed())
	}

	signed, err := bitcoin.MarshalWiredTransaction(msgTx, wire.WitnessEncoding, chain)
	if err != nil {
		return err
	}
	err = db.WriteAccountantKeys(ctx, keeper.SafeChainCurve(chain), keys)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", signed)
	return nil
}

func ObserverImportKeys(c *cli.Context) error {
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"))
	if err != nil {
		return err
	}

	db, err := observer.OpenSQLite3Store(mc.Observer.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	chain := c.Int("chain")
	publics, err := scanKeyList(c.String("list"), chain)
	if err != nil {
		return err
	}
	return db.WriteObserverKeys(ctx, byte(chain), publics)
}

func scanKeyList(path string, chain int) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return nil, fmt.Errorf("invalid chain %d", chain)
	}

	publics := make(map[string]string)
	for scanner.Scan() {
		hd := scanner.Text()
		hdp := strings.Split(hd, ":")
		if len(hdp) != 2 {
			return nil, fmt.Errorf("invalid pair %s", hd)
		}
		pub, code := hdp[0], hdp[1]
		err := bitcoin.VerifyHolderKey(pub)
		if err != nil {
			return nil, fmt.Errorf("invalid pub %s", hd)
		}

		chainCode, err := hex.DecodeString(code)
		if err != nil || len(chainCode) != 32 {
			return nil, fmt.Errorf("invalid code %s", hd)
		}
		publics[pub] = code
	}
	return publics, nil
}

func generateAccountantKey(chain byte) (*btcec.PrivateKey, string, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, "", err
	}
	pub := priv.PubKey().SerializeCompressed()
	awpkh, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub), bitcoin.NetConfig(chain))
	if err != nil {
		return nil, "", err
	}
	return priv, awpkh.EncodeAddress(), nil
}
