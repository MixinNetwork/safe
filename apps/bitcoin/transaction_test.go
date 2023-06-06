package bitcoin

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/test-go/testify/require"
)

func TestTransaction(t *testing.T) {
	require := require.New(t)
	pb, _ := hex.DecodeString("70736274ff0100a402000000016f934dc1d2393c04820e10141ce43c0ae46fa947c37476f1f8ce01c3cc5318180100000000ffffffff0310270000000000002200200d9f2feb04c9ffeb88025fd04ece1d73048d16840f8cb7ddfcabd754f77540a3d0d61c000000000022002070c3ec7f541da73d0eeb610b090b4d56d36dc8e6499b0a663fb34f224509dda50000000000000000126a108da610f6ee0b4666884c1c365ba8323f00000000095349474841534845532097965f513881cddb4d3547b4234f8379ce82045d4c2d1b493de00b071d5d98ff0001012be0fd1c000000000022002070c3ec7f541da73d0eeb610b090b4d56d36dc8e6499b0a663fb34f224509dda5220202bd2f73ffb81fda1a7b774be4e8ddcca9f776f7e5777f9c7fd246725ba034aa24473045022100f3e826bbfa0dfb8bf3e7739ef12ca74ff399026919862b3206c8a5353df9070502200f5dfc0952f71c6846e432d423e7186df858bc8f8f610aec5ef674d284a210d1220203d277643292197684bde44376b94a9c91783ce3e424bf390ac99bc90f3df9be60463044022070371e4bd5e698e2d07e83aa6cbbf018753fa12a6dc7c2862e3e55b6cb0ab16702203bf07bb87efddf8d7ae395ac6e0d393f1d34a95fd7e13570caa51d1c9a667aa8010304810000000105782103d277643292197684bde44376b94a9c91783ce3e424bf390ac99bc90f3df9be60ac7c2102bd2f73ffb81fda1a7b774be4e8ddcca9f776f7e5777f9c7fd246725ba034aa24ac937c82926321036a864e0321a9e8b84ac16fbc7e47f2401218700e37575680f908b5683a6f29ffad02c006b2926893528700000000")
	psbt, err := UnmarshalPartiallySignedTransaction(pb)
	require.Nil(err)
	require.NotNil(psbt)
	require.Equal(pb, psbt.Marshal())

	msgTx, err := psbt.SignedTransaction("03d277643292197684bde44376b94a9c91783ce3e424bf390ac99bc90f3df9be60", "02bd2f73ffb81fda1a7b774be4e8ddcca9f776f7e5777f9c7fd246725ba034aa24")
	require.Nil(err)

	raw, _ := MarshalWiredTransaction(msgTx, wire.BaseEncoding, ChainBitcoin)
	require.Equal("02000000016f934dc1d2393c04820e10141ce43c0ae46fa947c37476f1f8ce01c3cc5318180100000000ffffffff0310270000000000002200200d9f2feb04c9ffeb88025fd04ece1d73048d16840f8cb7ddfcabd754f77540a3d0d61c000000000022002070c3ec7f541da73d0eeb610b090b4d56d36dc8e6499b0a663fb34f224509dda50000000000000000126a108da610f6ee0b4666884c1c365ba8323f00000000", hex.EncodeToString(raw))
	raw, _ = MarshalWiredTransaction(msgTx, wire.WitnessEncoding, ChainBitcoin)
	require.Equal("020000000001016f934dc1d2393c04820e10141ce43c0ae46fa947c37476f1f8ce01c3cc5318180100000000ffffffff0310270000000000002200200d9f2feb04c9ffeb88025fd04ece1d73048d16840f8cb7ddfcabd754f77540a3d0d61c000000000022002070c3ec7f541da73d0eeb610b090b4d56d36dc8e6499b0a663fb34f224509dda50000000000000000126a108da610f6ee0b4666884c1c365ba8323f0400483045022100f3e826bbfa0dfb8bf3e7739ef12ca74ff399026919862b3206c8a5353df9070502200f5dfc0952f71c6846e432d423e7186df858bc8f8f610aec5ef674d284a210d181473044022070371e4bd5e698e2d07e83aa6cbbf018753fa12a6dc7c2862e3e55b6cb0ab16702203bf07bb87efddf8d7ae395ac6e0d393f1d34a95fd7e13570caa51d1c9a667aa881782103d277643292197684bde44376b94a9c91783ce3e424bf390ac99bc90f3df9be60ac7c2102bd2f73ffb81fda1a7b774be4e8ddcca9f776f7e5777f9c7fd246725ba034aa24ac937c82926321036a864e0321a9e8b84ac16fbc7e47f2401218700e37575680f908b5683a6f29ffad02c006b2926893528700000000", hex.EncodeToString(raw))
}