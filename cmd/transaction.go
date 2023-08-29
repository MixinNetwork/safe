package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/domains/mvm"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func GenerateTestTransactionProposal(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	kb, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return err
	}
	private, _ := btcec.PrivKeyFromBytes(kb)
	holder := testPublicKey(hex.EncodeToString(private.Serialize()))

	receiver, err := bitcoin.ParseAddress(c.String("address"), byte(chain))
	if err != nil {
		return err
	}

	addr := abi.GetFactoryAssetAddress(keeper.SafeBitcoinChainId, "BTC", "Bitcoin", holder)
	assetKey := strings.ToLower(addr.String())
	bondId := fetchAssetId(mvm.GenerateAssetId(assetKey).String())

	extra := []byte(receiver)
	sid := uuid.Must(uuid.NewV4()).String()
	amount := decimal.NewFromFloat(c.Float64("amount"))

	fmt.Println("session: " + sid)
	memo := testBuildHolderRequest(sid, holder, common.ActionBitcoinSafeProposeTransaction, extra)
	return makeKeeperPaymentRequest(c.String("config"), bondId, amount, sid, memo)
}

func GenerateTestTransactionApproval(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case keeper.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	kb, err := hex.DecodeString(c.String("key"))
	if err != nil {
		return err
	}
	holder, _ := btcec.PrivKeyFromBytes(kb)

	rb, err := hex.DecodeString(c.String("psbt"))
	if err != nil {
		return err
	}
	hpsbt, err := bitcoin.UnmarshalPartiallySignedTransaction(rb)
	if err != nil {
		return err
	}

	msgTx := hpsbt.UnsignedTx
	for idx := range msgTx.TxIn {
		hash := hpsbt.SigHash(idx)
		sig := ecdsa.Sign(holder, hash).Serialize()
		hpsbt.Inputs[idx].PartialSigs = []*psbt.PartialSig{{
			PubKey:    holder.PubKey().SerializeCompressed(),
			Signature: sig,
		}}
	}
	raw := hpsbt.Marshal()
	fmt.Printf("psbt: %x\n", raw)

	msg := bitcoin.HashMessageForSignature(msgTx.TxHash().String(), byte(chain))
	sig := ecdsa.Sign(holder, msg).Serialize()
	fmt.Printf("signature: %s\n", base64.RawURLEncoding.EncodeToString(sig))
	return nil
}

func fetchAssetId(mixinId string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	path := "https://api.mixin.one/network/assets/" + mixinId
	resp, err := client.Get(path)
	if err != nil {
		panic(mixinId)
	}
	defer resp.Body.Close()

	var body struct {
		Data struct {
			AssetId string `json:"asset_id"`
			MixinId string `json:"mixin_id"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Data.MixinId != mixinId {
		panic(mixinId)
	}
	return body.Data.AssetId
}
