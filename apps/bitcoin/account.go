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

func VerifyHolderKey(public string, chain byte) error {
	_, err := parseBitcoinCompressedPublicKey(public, chain)
	return err
}

func VerifySignatureDER(public string, msg, sig []byte, chain byte) error {
	pub, err := parseBitcoinCompressedPublicKey(public, chain)
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

func BuildWitnessScriptAccount(holder, signer, observer string, lock time.Duration, chain byte) (*WitnessScriptAccount, error) {
	var pubKeys []*btcutil.AddressPubKey
	for _, public := range []string{holder, signer, observer} {
		pub, err := parseBitcoinCompressedPublicKey(public, chain)
		if err != nil {
			return nil, fmt.Errorf("parseBitcoinCompressedPublicKey(%s) => %v", public, err)
		}
		pubKeys = append(pubKeys, pub)
	}

	if lock < TimeLockMinimum || lock > TimeLockMaximum {
		return nil, fmt.Errorf("time lock out of range %s", lock.String())
	}
	sequence := ParseSequence(lock)

	builder := txscript.NewScriptBuilder()
	// IF 2 ELSE
	builder.AddOp(txscript.OP_IF)
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_ELSE)
	// <LOCK> CHECKSEQUENCEVERIFY DROP
	builder.AddInt64(sequence)
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP)
	// <OBSERVER KEY> CHECKSIGVERIFY
	// 1 ENDIF
	builder.AddData(pubKeys[2].ScriptAddress())
	builder.AddOp(txscript.OP_CHECKSIGVERIFY)
	builder.AddInt64(1)
	builder.AddOp(txscript.OP_ENDIF)
	// <HOLDER KEY> <SIGNER KEY> 2 CHECKMULTISIG
	builder.AddData(pubKeys[0].ScriptAddress())
	builder.AddData(pubKeys[1].ScriptAddress())
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_CHECKMULTISIG)

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
	pub, err := parseBitcoinCompressedPublicKey(accountant, chain)
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

func parseBitcoinCompressedPublicKey(public string, chain byte) (*btcutil.AddressPubKey, error) {
	pub, err := hex.DecodeString(public)
	if err != nil {
		return nil, err
	}
	return btcutil.NewAddressPubKey(pub, netConfig(chain))
}

func netConfig(chain byte) *chaincfg.Params {
	switch chain {
	case ChainBitcoin:
		return &chaincfg.MainNetParams
	case ChainLitecoin:
		return &chaincfg.Params{
			Bech32HRPSegwit:         "ltc",
			PubKeyHashAddrID:        0x30,
			ScriptHashAddrID:        0x32,
			WitnessPubKeyHashAddrID: 0x06,
			WitnessScriptHashAddrID: 0x0A,
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
