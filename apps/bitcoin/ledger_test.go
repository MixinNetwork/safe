package bitcoin

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/ecdsa"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/test-go/testify/require"
)

func TestLedgerBitcoin(t *testing.T) {
	require := require.New(t)
	msg := "Mixin Safe"

	// hwi.py enumerate
	// [{"type": "ledger", "model": "ledger_nano_x", "label": null, "path": "DevSrvsID:4295227454", "fingerprint": "9c03cfaf", "needs_pin_sent": false, "needs_passphrase_sent": false}]
	masterFinger := "9c03cfaf"
	// hwi.py --device-type ledger getxpub "m"
	// {"xpub": "xpub661MyMwAqRbcEtbkem82xkmWsp3MAWkf8fjmiQRpUT8M5ncmcgtwdVSRCH89Cde1w4KMZkNRvr6SxLHY3JFwD1TDtfBNsAEjVqGWD697YxH"}
	masterXPub := "xpub661MyMwAqRbcEtbkem82xkmWsp3MAWkf8fjmiQRpUT8M5ncmcgtwdVSRCH89Cde1w4KMZkNRvr6SxLHY3JFwD1TDtfBNsAEjVqGWD697YxH"
	// hwi.py --device-type ledger getxpub "m/44'/0'/0'"
	// {"xpub": "xpub6Ci9Nfuo4VkA6gzSdKQK6XYztQ65B52gyTQ4ShB7unGB8tfAqVLS6Nw3v62onLJXEzp8H2UarXRt7nBnAFX7FpwjaSBgo2M7AWp81y4eg1w"}
	hardenXPub := "xpub6Ci9Nfuo4VkA6gzSdKQK6XYztQ65B52gyTQ4ShB7unGB8tfAqVLS6Nw3v62onLJXEzp8H2UarXRt7nBnAFX7FpwjaSBgo2M7AWp81y4eg1w"
	// hwi.py --device-type ledger getxpub "m/44'/0'/0'/0/0"
	// {"xpub": "xpub6FTuqZMKwrYUrnfHZXs1NsfnoFNXQFXFajicGCvnv8W3fM7zU1hkarEgfazW11p5JsCNcF1L6NpLoucJ2iPy23KE1KMsABRBzsZmAa4xQy4"}
	deriveXPub := "xpub6FTuqZMKwrYUrnfHZXs1NsfnoFNXQFXFajicGCvnv8W3fM7zU1hkarEgfazW11p5JsCNcF1L6NpLoucJ2iPy23KE1KMsABRBzsZmAa4xQy4"
	// hwi.py --device-type ledger signmessage "Mixin Safe" "m/44'/0'/0'/0/0"
	// {"signature": "IEqfwZFSNu2B2tu2d84ZQW4Cd1xm5sTcQoz8Ek5i/ChvG1AGhYbTqsmceqyaXMNvLdJzWN1U0jJlsyMRxM3Rtu4="}
	deriveSig := "IEqfwZFSNu2B2tu2d84ZQW4Cd1xm5sTcQoz8Ek5i/ChvG1AGhYbTqsmceqyaXMNvLdJzWN1U0jJlsyMRxM3Rtu4="

	xPub, err := hdkeychain.NewKeyFromString(masterXPub)
	require.Nil(err)
	ecPub, err := xPub.ECPubKey()
	require.Nil(err)
	finger := btcutil.Hash160(ecPub.SerializeCompressed())[:4]
	require.Equal(masterFinger, hex.EncodeToString(finger))

	xPub, _ = hdkeychain.NewKeyFromString(hardenXPub)
	xPub, _ = xPub.Derive(0)
	xPub, _ = xPub.Derive(0)
	require.Equal(deriveXPub, xPub.String())

	xPub, _ = hdkeychain.NewKeyFromString(deriveXPub)
	ecPub, _ = xPub.ECPubKey()
	sig, _ := base64.StdEncoding.DecodeString(deriveSig)
	es, err := ecdsa.ParseSignature(curve.Secp256k1{}, sig)
	require.Nil(err)
	holder := hex.EncodeToString(ecPub.SerializeCompressed())
	messageHash := HashMessageForSignature(msg, ChainBitcoin)
	err = VerifySignatureDER(holder, messageHash, es.SerializeDER())
	require.Nil(err)
	require.Equal("02e1d3a1e1b7b6098792662ffd960fb0a4011bc73986d66336dcf40cc8ca37b4cd", holder)

	signerPub := "02bf0a7fa4b7905a0de5ab60a5322529e1a591ddd1ee53df82e751e8adb4bed08c"
	signerChainCode := "f555b08a9871213c0d52fee12e1bd365990b956880491b2b1a106f84584aa3a2"
	signerFinger := "61315bdf"
	chainCode, _ := hex.DecodeString(signerChainCode)
	signerXPub, signerPub, err := DeriveBIP32(signerPub, chainCode)
	require.Nil(err)
	require.Equal("xpub661MyMwAqRbcGz6ujRJnzrBvWrkz2NdNzYc3ZGBMVPmPBTHomqTiX5RrcTZVYZR2jM75oBU1UFssyMFqHV6GDsreibF2tPMbCcSPnTfqwhM", signerXPub)
	require.Equal("02bf0a7fa4b7905a0de5ab60a5322529e1a591ddd1ee53df82e751e8adb4bed08c", signerPub)
	pub, _ := hex.DecodeString(signerPub)
	finger = btcutil.Hash160(pub)[:4]
	require.Equal(signerFinger, hex.EncodeToString(finger))
	signerDeriveXPub, signerDerivePub, _ := DeriveBIP32(signerPub, chainCode, 0, 0)
	require.Equal("xpub6B7hvMJYkHi2QSUjkitqK3u9Ep1ikfD31LhpqN8kZQpRpKEe1MEucK8TeEQcSHtBRCrfMiTjtYTqHDBxoGidWbLsUqMfZ1WDSm6uczM7TaY", signerDeriveXPub)
	require.Equal("02339baf159c94cc116562d609097ff3c3bd340a34b9f7d50cc22b8d520301a7c9", signerDerivePub)

	observerPub := "02442850035ee4d6f322e58e6e0ddc25b81d5fa3ca693000f992bb198c967d4a5b"
	observerChainCode := "f20e9476f2395c49ed80cc62fe6022a8d83121cb48ee01fdfaa77b31b01c031d"
	observerFinger := "03d4ea2b"
	chainCode, _ = hex.DecodeString(observerChainCode)
	observerXPub, observerPub, err := DeriveBIP32(observerPub, chainCode)
	require.Nil(err)
	require.Equal("xpub661MyMwAqRbcGxD8XPvZ3fQy7WqAJBvdrEH1kwg1SGDAQprmpGvHsz5rVytTrfFmLTzRiSAMo43R7DhzjR3ucQH5UxBvFB9YDUZVQFiyDKG", observerXPub)
	require.Equal("02442850035ee4d6f322e58e6e0ddc25b81d5fa3ca693000f992bb198c967d4a5b", observerPub)
	pub, _ = hex.DecodeString(observerPub)
	finger = btcutil.Hash160(pub)[:4]
	require.Equal(observerFinger, hex.EncodeToString(finger))
	observerDeriveXPub, observerDerivePub, _ := DeriveBIP32(observerPub, chainCode, 0, 0)
	require.Equal("xpub6B7tgSvpJBiU2quZk3DuNt5N7DiqeDfxGc7hQPnxie48GHdDmBG1CHn2L3BWBUqvCfS3V9z8CTDuLrxRQ9xQuB5jzMUYPJprwbEvftt6TBt", observerDeriveXPub)
	require.Equal("0281b901b31b51b93095249db49238299e9292e3c356b302c05b5d5b27dca99d1f", observerDerivePub)

	// hwi.py --device-type ledger registerpolicy --name "Safe Test" --policy "wsh(thresh(2,pk(@0/**),s:pk(@1/**),sj:and_v(v:pk(@2/**),n:older(432))))" --keys "[\"[9c03cfaf/44'/0'/0']xpub6Ci9Nfuo4VkA6gzSdKQK6XYztQ65B52gyTQ4ShB7unGB8tfAqVLS6Nw3v62onLJXEzp8H2UarXRt7nBnAFX7FpwjaSBgo2M7AWp81y4eg1w\",\"[61315bdf]xpub661MyMwAqRbcGz6ujRJnzrBvWrkz2NdNzYc3ZGBMVPmPBTHomqTiX5RrcTZVYZR2jM75oBU1UFssyMFqHV6GDsreibF2tPMbCcSPnTfqwhM\",\"[03d4ea2b]xpub661MyMwAqRbcGxD8XPvZ3fQy7WqAJBvdrEH1kwg1SGDAQprmpGvHsz5rVytTrfFmLTzRiSAMo43R7DhzjR3ucQH5UxBvFB9YDUZVQFiyDKG\"]"
	// {"proof_of_registration": "614769273c25e8e1f3e8918fcc9d4bab0548ba2a2f590dd8f15146f411b330f5"}
	// hwi.py --device-type ledger displayaddress --name "Safe Test" --policy "wsh(thresh(2,pk(@0/**),s:pk(@1/**),sj:and_v(v:pk(@2/**),n:older(432))))" --keys "[\"[9c03cfaf/44'/0'/0']xpub6Ci9Nfuo4VkA6gzSdKQK6XYztQ65B52gyTQ4ShB7unGB8tfAqVLS6Nw3v62onLJXEzp8H2UarXRt7nBnAFX7FpwjaSBgo2M7AWp81y4eg1w\",\"[61315bdf]xpub661MyMwAqRbcGz6ujRJnzrBvWrkz2NdNzYc3ZGBMVPmPBTHomqTiX5RrcTZVYZR2jM75oBU1UFssyMFqHV6GDsreibF2tPMbCcSPnTfqwhM\",\"[03d4ea2b]xpub661MyMwAqRbcGxD8XPvZ3fQy7WqAJBvdrEH1kwg1SGDAQprmpGvHsz5rVytTrfFmLTzRiSAMo43R7DhzjR3ucQH5UxBvFB9YDUZVQFiyDKG\"]"  --extra '{"proof_of_registration": "614769273c25e8e1f3e8918fcc9d4bab0548ba2a2f590dd8f15146f411b330f5"}' --index 0
	// {"address": "bc1qrgks3frgprw92rkey7yqs5ge57jddep52es6yn54mudl3kfwvxpsa4r46k"}
	wsa, err := BuildWitnessScriptAccount(holder, signerDerivePub, observerDerivePub, time.Hour*24*3, ChainBitcoin)
	require.Nil(err)
	require.Equal("bc1qrgks3frgprw92rkey7yqs5ge57jddep52es6yn54mudl3kfwvxpsa4r46k", wsa.Address)

	// hwi.py --device-type ledger getxpub "m/44'/0'/0'/0/1"
	// {"xpub": "xpub6FTuqZMKwrYUtfh2sbKj7J9UzzRB9Cq9vrLdzZXA3UiQs7uf8VETXvgvjiehifDaWLVTfCiX9Fm26dZp3jYftMDuCrMmKM6Eq24Lkz9BXxb"}
	// hwi.py --device-type ledger displayaddress --name "Safe Test" --policy "wsh(thresh(2,pk(@0/**),s:pk(@1/**),sj:and_v(v:pk(@2/**),n:older(432))))" --keys "[\"[9c03cfaf/44'/0'/0']xpub6Ci9Nfuo4VkA6gzSdKQK6XYztQ65B52gyTQ4ShB7unGB8tfAqVLS6Nw3v62onLJXEzp8H2UarXRt7nBnAFX7FpwjaSBgo2M7AWp81y4eg1w\",\"[61315bdf]xpub661MyMwAqRbcGz6ujRJnzrBvWrkz2NdNzYc3ZGBMVPmPBTHomqTiX5RrcTZVYZR2jM75oBU1UFssyMFqHV6GDsreibF2tPMbCcSPnTfqwhM\",\"[03d4ea2b]xpub661MyMwAqRbcGxD8XPvZ3fQy7WqAJBvdrEH1kwg1SGDAQprmpGvHsz5rVytTrfFmLTzRiSAMo43R7DhzjR3ucQH5UxBvFB9YDUZVQFiyDKG\"]"  --extra '{"proof_of_registration": "614769273c25e8e1f3e8918fcc9d4bab0548ba2a2f590dd8f15146f411b330f5"}' --index 1
	// {"address": "bc1qdj9sa2fa49rw77s468zfzsrmpdh805m98ctyypydnnt0ppxy802qaxd028"}
	xPub, _ = hdkeychain.NewKeyFromString("xpub6FTuqZMKwrYUtfh2sbKj7J9UzzRB9Cq9vrLdzZXA3UiQs7uf8VETXvgvjiehifDaWLVTfCiX9Fm26dZp3jYftMDuCrMmKM6Eq24Lkz9BXxb")
	ecPub, _ = xPub.ECPubKey()
	holder = hex.EncodeToString(ecPub.SerializeCompressed())
	chainCode, _ = hex.DecodeString(signerChainCode)
	_, signerDerivePub, _ = DeriveBIP32(signerPub, chainCode, 0, 1)
	chainCode, _ = hex.DecodeString(observerChainCode)
	_, observerDerivePub, _ = DeriveBIP32(observerPub, chainCode, 0, 1)
	wsa, _ = BuildWitnessScriptAccount(holder, signerDerivePub, observerDerivePub, time.Hour*24*3, ChainBitcoin)
	require.Nil(err)
	require.Equal("bc1qdj9sa2fa49rw77s468zfzsrmpdh805m98ctyypydnnt0ppxy802qaxd028", wsa.Address)
}
