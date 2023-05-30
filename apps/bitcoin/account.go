package bitcoin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type WitnessScriptAccount struct {
	Sequence uint32
	Script   []byte
	Address  string
}

type WitnessKeyAccount struct {
	Script  []byte
	Address string
}

func (wsa *WitnessScriptAccount) MarshalWithAccountant(accountant string) []byte {
	enc := common.NewEncoder()
	enc.WriteUint64(uint64(wsa.Sequence))
	writeBytes(enc, wsa.Script)
	writeBytes(enc, []byte(wsa.Address))
	writeBytes(enc, []byte(accountant))
	return enc.Bytes()
}

func UnmarshalWitnessScriptAccountWitAccountant(extra []byte) (*WitnessScriptAccount, string, error) {
	dec := common.NewDecoder(extra)
	sequence, err := dec.ReadUint64()
	if err != nil {
		return nil, "", err
	}
	script, err := dec.ReadBytes()
	if err != nil {
		return nil, "", err
	}
	addr, err := dec.ReadBytes()
	if err != nil {
		return nil, "", err
	}
	accountant, err := dec.ReadBytes()
	if err != nil {
		return nil, "", err
	}
	return &WitnessScriptAccount{
		Sequence: uint32(sequence),
		Script:   script,
		Address:  string(addr),
	}, string(accountant), nil
}

func EncodeAddress(script []byte, chain byte) (string, error) {
	typ := checkScriptType(script)
	switch typ {
	case InputTypeP2WSHMultisigHolderSigner:
		msh := sha256.Sum256(script)
		mwsh, err := btcutil.NewAddressWitnessScriptHash(msh[:], netConfig(chain))
		if err != nil {
			return "", err
		}
		return mwsh.EncodeAddress(), nil
	case InputTypeP2WPKHAccoutant:
		msh := btcutil.Hash160(script)
		wph, err := btcutil.NewAddressWitnessPubKeyHash(msh, netConfig(chain))
		if err != nil {
			return "", err
		}
		return wph.EncodeAddress(), nil
	default:
		panic(typ)
	}
}

func VerifyHolderKey(public string) error {
	_, err := parseBitcoinCompressedPublicKey(public)
	return err
}

func VerifySignatureDER(public string, msg, sig []byte) error {
	pub, err := parseBitcoinCompressedPublicKey(public)
	if err != nil {
		return err
	}
	der, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return err
	}
	if der.Verify(msg, pub.PubKey()) {
		return nil
	}
	return fmt.Errorf("bitcoin.VerifySignature(%s, %x, %x)", public, msg, sig)
}

// thresh(2,pk(HOLDER),pk(SINGER),and(pk(OBSERVER),older(12960)))
// thresh(2,pk(HOLDER),s:pk(SINGER),sj:and_v(v:pk(OBSERVER),n:older(12960)))
//
// <HOLDER> OP_CHECKSIG OP_SWAP <SINGER> OP_CHECKSIG OP_ADD OP_SWAP OP_SIZE
// OP_0NOTEQUAL OP_IF
// <OBSERVER> OP_CHECKSIGVERIFY <a032> OP_CHECKSEQUENCEVERIFY OP_0NOTEQUAL
// OP_ENDIF
// OP_ADD 2 OP_EQUAL
func BuildWitnessScriptAccount(holder, signer, observer string, lock time.Duration, chain byte) (*WitnessScriptAccount, error) {
	var pubKeys []*btcutil.AddressPubKey
	for _, public := range []string{holder, signer, observer} {
		pub, err := parseBitcoinCompressedPublicKey(public)
		if err != nil {
			return nil, fmt.Errorf("parseBitcoinCompressedPublicKey(%s) => %v", public, err)
		}
		pubKeys = append(pubKeys, pub)
	}

	if lock < TimeLockMinimum || lock > TimeLockMaximum {
		return nil, fmt.Errorf("time lock out of range %s", lock.String())
	}
	sequence := ParseSequence(lock, chain)

	builder := txscript.NewScriptBuilder()
	builder.AddData(pubKeys[0].ScriptAddress())
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_SWAP)
	builder.AddData(pubKeys[1].ScriptAddress())
	builder.AddOp(txscript.OP_CHECKSIG)
	builder.AddOp(txscript.OP_ADD)
	builder.AddOp(txscript.OP_SWAP)
	builder.AddOp(txscript.OP_SIZE)
	builder.AddOp(txscript.OP_0NOTEQUAL)
	builder.AddOp(txscript.OP_IF)
	builder.AddData(pubKeys[2].ScriptAddress())
	builder.AddOp(txscript.OP_CHECKSIGVERIFY)
	builder.AddInt64(sequence)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_0NOTEQUAL)
	builder.AddOp(txscript.OP_ENDIF)
	builder.AddOp(txscript.OP_ADD)
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_EQUAL)

	script, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("build.Script() => %v", err)
	}
	msh := sha256.Sum256(script)
	mwsh, err := btcutil.NewAddressWitnessScriptHash(msh[:], netConfig(chain))
	if err != nil {
		return nil, fmt.Errorf("btcutil.NewAddressWitnessScriptHash(%x) => %v", msh[:], err)
	}

	return &WitnessScriptAccount{
		Sequence: uint32(sequence),
		Script:   script,
		Address:  mwsh.EncodeAddress(),
	}, nil
}

func BuildWitnessKeyAccount(accountant string, chain byte) (*WitnessKeyAccount, error) {
	pub, err := parseBitcoinCompressedPublicKey(accountant)
	if err != nil {
		return nil, err
	}
	script := pub.ScriptAddress()
	wpkh := btcutil.Hash160(script)
	wph, err := btcutil.NewAddressWitnessPubKeyHash(wpkh, netConfig(chain))
	if err != nil {
		return nil, err
	}
	return &WitnessKeyAccount{
		Script:  script,
		Address: wph.EncodeAddress(),
	}, nil
}

func CheckMultisigHolderSignerScript(script []byte) bool {
	return checkScriptType(script) == InputTypeP2WSHMultisigHolderSigner
}

func parseBitcoinCompressedPublicKey(public string) (*btcutil.AddressPubKey, error) {
	pub, err := hex.DecodeString(public)
	if err != nil {
		return nil, err
	}
	return btcutil.NewAddressPubKey(pub, netConfig(ChainBitcoin))
}

func protocolVersion(chain byte) uint32 {
	switch chain {
	case ChainBitcoin:
		return wire.ProtocolVersion
	case ChainLitecoin:
		return 70015
	default:
		panic(chain)
	}
}

func init() {
	ltcParams := netConfig(ChainLitecoin)
	err := chaincfg.Register(ltcParams)
	if err != nil {
		panic(err)
	}
}

func netConfig(chain byte) *chaincfg.Params {
	switch chain {
	case ChainBitcoin:
		return &chaincfg.MainNetParams
	case ChainLitecoin:
		return &chaincfg.Params{
			Net:             0xdbb6c0fb,
			Bech32HRPSegwit: "ltc",

			PubKeyHashAddrID:        0x30,
			ScriptHashAddrID:        0x32,
			WitnessPubKeyHashAddrID: 0x06,
			WitnessScriptHashAddrID: 0x0A,

			HDPublicKeyID:  [4]byte{0x01, 0x9d, 0xa4, 0x64},
			HDPrivateKeyID: [4]byte{0x01, 0x9d, 0x9c, 0xfe},
		}
	default:
		panic(chain)
	}
}

func checkScriptType(script []byte) int {
	if len(script) == 33 {
		return InputTypeP2WPKHAccoutant
	}
	if len(script) > 100 {
		return InputTypeP2WSHMultisigHolderSigner
	}
	panic(hex.EncodeToString(script))
}
