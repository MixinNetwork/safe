package cmd

import (
	"bufio"
	"context"
	ce "crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/observer"
	"github.com/MixinNetwork/safe/util"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	gc "github.com/ethereum/go-ethereum/crypto"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/urfave/cli/v2"
)

func ObserverBootCmd(c *cli.Context) error {
	ctx := context.Background()

	version := c.App.Metadata["VERSION"].(string)
	ua := fmt.Sprintf("Mixin Safe Observer (%s)", version)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"), "observer")
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
		AppID:             mc.Observer.App.AppId,
		SessionID:         mc.Observer.App.SessionId,
		SessionPrivateKey: mc.Observer.App.SessionPrivateKey,
		ServerPublicKey:   mc.Observer.App.ServerPublicKey,
	})
	if err != nil {
		return err
	}
	me, err := mixin.UserMe(ctx)
	if err != nil {
		return err
	}
	key, err := mixinnet.ParseKeyWithPub(mc.Observer.App.SpendPrivateKey, me.SpendPublicKey)
	if err != nil {
		return err
	}
	mc.Observer.App.SpendPrivateKey = key.String()

	node := observer.NewNode(db, kd, mc.Observer, mc.Keeper.MTG, mixin)
	readme := c.App.Metadata["README"].(string)
	go node.StartHTTP(version, readme)
	if mc.Dev.Network == config.MainNetworkName {
		go node.Blaze(ctx)
	}
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

	kb, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return fmt.Errorf("invalid private key hex %s", c.String("key"))
	}
	priv, pub := btcec.PrivKeyFromBytes(kb)

	mc, err := config.ReadConfiguration(c.String("config"), "observer")
	if err != nil {
		return err
	}
	db, err := observer.OpenSQLite3Store(mc.Observer.StoreDir + "/safe.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()

	input := util.SplitIds(c.String("input"), ":")[0]
	index, _ := strconv.ParseUint(util.SplitIds(c.String("input"), ":")[1], 10, 32)
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
	err = db.WriteAccountantKeys(ctx, common.SafeChainCurve(chain), keys)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", signed)
	return nil
}

func ObserverImportKeys(c *cli.Context) error {
	ctx := context.Background()

	mc, err := config.ReadConfiguration(c.String("config"), "observer")
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
	case common.SafeChainBitcoin:
	case common.SafeChainEthereum:
	default:
		return nil, fmt.Errorf("invalid chain %d", chain)
	}

	publics := make(map[string]string)
	for scanner.Scan() {
		hd := scanner.Text()
		hdp := util.SplitIds(hd, ":")
		if len(hdp) != 3 {
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

func GenerateObserverKeys(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case common.SafeChainBitcoin:
	case common.SafeChainEthereum:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	pubF, err := os.Create(c.String("list") + ".pub")
	if err != nil {
		return err
	}
	defer pubF.Close()

	const harden = uint(0x80000000)
	seed := c.String("seed")

	offset, count := c.Uint("offset"), c.Uint("count")
	if offset <= 0 || offset >= harden/1024 {
		panic(offset)
	}
	if count <= 0 || count >= 1024*16 {
		panic(count)
	}
	for i := uint(0); i < count; i++ {
		index := uint32(offset + i)
		if index > uint32(harden/2) {
			panic(index)
		}
		account, err := generateObserverAccount(byte(chain), index, seed)
		if err != nil {
			panic(err)
		}
		line := fmt.Sprintf("%x:%x:%s", account.Public, account.ChainCode, account.Fingerprint)
		if c.Bool("private") {
			line = fmt.Sprintf("%s:%x", line, account.Private)
		}
		_, err = pubF.WriteString(line + "\n")
		if err != nil {
			panic(err)
		}
	}
	return nil
}

type Account struct {
	Private     []byte
	Public      []byte
	ChainCode   []byte
	Fingerprint string
}

// seed = m'/1396786757'/coin'/account'
func generateObserverAccount(chain byte, account uint32, masterSeed string) (*Account, error) {
	seed, err := hex.DecodeString(masterSeed)
	if err != nil {
		panic(err)
	}

	// important to always use the bitcoin params for any chains
	master, err := hdkeychain.NewMaster(seed, bitcoin.NetConfig(bitcoin.ChainBitcoin))
	if err != nil {
		panic(err)
	}
	if !master.IsPrivate() {
		panic(master.String())
	}

	base := uint32(hdkeychain.HardenedKeyStart)
	priv44, err := master.Derive(base + 1396786757)
	if err != nil {
		panic(err)
	}
	privCoin, err := priv44.Derive(base + uint32(chain))
	if err != nil {
		panic(err)
	}
	privAcc, err := privCoin.Derive(base + account)
	if err != nil {
		return nil, err
	}

	epriv, err := privAcc.ECPrivKey()
	if err != nil {
		panic(err)
	}

	ash := crypto.Blake3Hash(epriv.Serialize())
	hmac512 := hmac.New(sha512.New, privAcc.ChainCode())
	_, _ = hmac512.Write(ash[:])
	ilr := hmac512.Sum(nil)
	if len(ilr) != 64 {
		panic(len(ilr))
	}

	priv := crypto.Sha256Hash(ilr[:len(ilr)/2])
	chainCode := crypto.Blake3Hash(ilr[len(ilr)/2:])
	finger := btcutil.Hash160([]byte(masterSeed))[:4]
	finger = binary.BigEndian.AppendUint32(finger, account)
	res := &Account{
		Private:     priv[:],
		ChainCode:   chainCode[:],
		Fingerprint: fmt.Sprintf("%X", finger),
	}

	switch chain {
	case bitcoin.ChainBitcoin:
		_, publicKey := btcec.PrivKeyFromBytes(res.Private)
		res.Public = publicKey.SerializeCompressed()
		err = bitcoin.CheckDerivation(hex.EncodeToString(res.Public), res.ChainCode, 100)
		if err != nil {
			panic(err)
		}
	case ethereum.ChainEthereum:
		privateKey, err := gc.ToECDSA(res.Private)
		if err != nil {
			panic(err)
		}
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ce.PublicKey)
		if !ok {
			panic("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		}
		res.Public = gc.CompressPubkey(publicKeyECDSA)
	default:
		panic(chain)
	}

	return res, nil
}
