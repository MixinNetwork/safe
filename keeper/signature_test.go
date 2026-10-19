package keeper

import (
	"encoding/hex"
	"testing"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestBitcoinRemovalSignatureAuthorization(t *testing.T) {
	for _, chain := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin} {
		t.Run(common.SafeChainAssetId(chain), func(t *testing.T) {
			node, closeNode := coverageKeeperNode(t)
			t.Cleanup(closeNode)
			ctx := t.Context()
			safe := &store.Safe{
				Chain: chain, Holder: testPublicKey(testBitcoinKeyHolderPrivate),
				Observer: testPublicKey(testBitcoinKeyObserverPrivate), Path: hex.EncodeToString(bitcoinDefaultDerivationPath()),
			}
			out := coverageKeeperOutput(node, uuid.Must(uuid.NewV4()).String(), common.ActionObserverAddKey, common.CurveSecp256k1ECDSABitcoin, nil, "observer")
			req, err := node.parseRequest(out)
			require.NoError(t, err)
			req.Holder = safe.Observer
			require.NoError(t, node.store.WriteRequestIfNotExist(ctx, req))
			require.NoError(t, node.store.WriteKeyFromRequest(ctx, req, common.RequestRoleObserver, common.DecodeHexOrPanic(testBitcoinKeyObserverChainCode), common.RequestFlagNone))

			const message = "REVOKE:request:transaction"
			hash := bitcoin.HashMessageForSignature(message, chain)
			holder, _ := btcec.PrivKeyFromBytes(common.DecodeHexOrPanic(testBitcoinKeyHolderPrivate))
			rootObserver, _ := btcec.PrivKeyFromBytes(common.DecodeHexOrPanic(testBitcoinKeyObserverPrivate))
			outsider, _ := btcec.PrivKeyFromBytes(common.DecodeHexOrPanic(testBitcoinKeyDummyHolderPrivate))
			for _, test := range []struct {
				name string
				key  *btcec.PrivateKey
				want bool
			}{
				{"holder", holder, true},
				{"derived observer", testGetDerivedObserverPrivate(require.New(t)), true},
				{"underived observer", rootObserver, false},
				{"unrelated key", outsider, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					sig := ecdsa.Sign(test.key, hash).Serialize()
					err := node.verifyRemoveMessageSignatureWithHolderOrObserver(ctx, safe, message, sig)
					if test.want {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
					}
					require.Error(t, node.verifyRemoveMessageSignatureWithHolderOrObserver(ctx, safe, message+"-changed", sig))
				})
			}
			require.Error(t, node.verifyRemoveMessageSignatureWithHolderOrObserver(ctx, safe, message, []byte("invalid DER")))
		})
	}
}

func TestEthereumRemovalSignatureAuthorization(t *testing.T) {
	node := &Node{}
	for _, chain := range []byte{common.SafeChainEthereum, common.SafeChainPolygon} {
		t.Run(common.SafeChainAssetId(chain), func(t *testing.T) {
			safe := &store.Safe{Chain: chain, Holder: testEthereumPublicKey(testEthereumKeyHolder), Observer: testEthereumPublicKey(testEthereumKeyObserver)}
			const message = "REVOKE:request:transaction"
			for _, test := range []struct {
				name string
				key  string
				want bool
			}{
				{"holder", testEthereumKeyHolder, true},
				{"observer", testEthereumKeyObserver, true},
				{"unrelated key", testEthereumKeyDummyHolder, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					sig := testEthereumSignMessage(require.New(t), test.key, []byte(message))
					err := node.verifyRemoveMessageSignatureWithHolderOrObserver(t.Context(), safe, message, sig)
					if test.want {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
					}
					require.Error(t, node.verifyRemoveMessageSignatureWithHolderOrObserver(t.Context(), safe, message+"-changed", sig))
				})
			}
			require.Error(t, node.verifyRemoveMessageSignatureWithHolderOrObserver(t.Context(), safe, message, nil))
		})
	}
}

func TestEthereumTransactionSignatureAuthorization(t *testing.T) {
	node := &Node{}
	safe := &store.Safe{
		Holder: testEthereumPublicKey(testEthereumKeyHolder), Signer: testEthereumPublicKey(testEthereumKeyDummyHolder),
		Observer: testEthereumPublicKey(testEthereumKeyObserver),
	}
	_, owners := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	keys := map[string]string{safe.Holder: testEthereumKeyHolder, safe.Signer: testEthereumKeyDummyHolder, safe.Observer: testEthereumKeyObserver}
	for index, public := range owners {
		t.Run(public, func(t *testing.T) {
			tx := &ethereum.SafeTransaction{Message: []byte("safe transaction"), Signatures: make([][]byte, len(owners))}
			signed, err := node.checkEthereumTransactionSignedBy(safe, tx, public)
			require.NoError(t, err)
			require.False(t, signed)
			sig := testEthereumSignMessage(require.New(t), keys[public], tx.Message)
			tx.Signatures[index] = sig
			for _, owner := range owners {
				signed, err = node.checkEthereumTransactionSignedBy(safe, tx, owner)
				require.NoError(t, err)
				require.Equal(t, owner == public, signed)
			}
			// Safe transactions require the eth_sign recovery byte, even when
			// the signature itself is otherwise valid for this owner.
			tx.Signatures[index] = append([]byte(nil), sig...)
			tx.Signatures[index][64] -= 4
			signed, err = node.checkEthereumTransactionSignedBy(safe, tx, public)
			require.NoError(t, err)
			require.False(t, signed)
			tx.Signatures[index] = sig
			tx.Message = []byte("different transaction")
			signed, err = node.checkEthereumTransactionSignedBy(safe, tx, public)
			require.NoError(t, err)
			require.False(t, signed)
		})
	}
}
