package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/config"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

func GenerateTestTransactionProposal(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case common.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}
	amount, err := decimal.NewFromString(c.String("amount"))
	if err != nil || amount.Sign() <= 0 || amount.GreaterThan(decimal.New(math.MaxInt64, -bitcoin.ValuePrecision)) || !amount.Equal(amount.Truncate(bitcoin.ValuePrecision)) {
		return fmt.Errorf("invalid bitcoin amount %q", c.String("amount"))
	}

	private, err := parseBitcoinPrivateKey(c.String("key"))
	if err != nil {
		return err
	}
	holder := testPublicKey(hex.EncodeToString(private.Serialize()))

	_, err = bitcoin.ParseAddress(c.String("address"), byte(chain))
	if err != nil {
		return err
	}

	head, err := uuid.FromString(c.String("head"))
	if err != nil || head.IsNil() {
		return fmt.Errorf("invalid network info request id")
	}
	mc, err := config.ReadConfiguration(c.String("config"), "keeper")
	if err != nil {
		return err
	}
	abi.InitFactoryContractAddress(mc.Keeper.PolygonFactoryAddress)
	addr := abi.GetFactoryAssetAddress(mc.Keeper.PolygonKeeperDepositEntry, common.SafeBitcoinChainId, "BTC", "Bitcoin", holder)
	assetKey := strings.ToLower(addr.String())
	bondId := ethereum.GenerateAssetId(common.SafeChainPolygon, assetKey)

	extra := append([]byte{common.FlagProposeNormalTransaction}, head.Bytes()...)
	extra = append(extra, c.String("address")...)
	sid := uuid.Must(uuid.NewV4()).String()

	memo := testBuildHolderRequest(sid, holder, common.ActionBitcoinSafeProposeTransaction, extra)
	return makeKeeperPaymentRequest(c.String("config"), bondId, amount, sid, memo)
}

func GenerateTestTransactionApproval(c *cli.Context) error {
	chain := c.Int("chain")
	switch chain {
	case common.SafeChainBitcoin:
	default:
		return fmt.Errorf("invalid chain %d", chain)
	}

	holder, err := parseBitcoinPrivateKey(c.String("key"))
	if err != nil {
		return err
	}

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
