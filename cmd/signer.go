package cmd

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/messenger"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
	"github.com/gofrs/uuid/v5"
	"github.com/mdp/qrterminal"
	"github.com/shopspring/decimal"
	"github.com/urfave/cli/v2"
)

// FIXME remove this
func mtgFix(ctx context.Context, path string) {
	// store update actions state to initial
	// store.FinishAction()
	db, err := common.OpenSQLite3Store(path, "")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	key := "FIX:3db5263a878192bbf6525a41ffc743d9deb330b8"
	row := db.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&key)
	if err == sql.ErrNoRows {
	} else if err != nil {
		panic(err)
	} else {
		return
	}

	txn, err := db.BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}
	defer txn.Rollback()

	_, err = txn.ExecContext(ctx, "UPDATE actions SET action_state=10 WHERE output_id=?", aa.OutputId)
	if err != nil {
		panic(err)
	}
	_, err = txn.ExecContext(ctx, "UPDATE actions SET action_state=10 WHERE output_id=?", ba.OutputId)
	if err != nil {
		panic(err)
	}

	_, err = txn.ExecContext(ctx, "INSERT INTO properties (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)",
		key, "actions", time.Now().UTC(), time.Now().UTC())
	if err != nil {
		panic(err)
	}
	err = txn.Commit()
	if err != nil {
		panic(err)
	}
}

var (
	aa = &mtg.Action{
		OutputId: "fefc4470-7e29-3a30-8c65-a92f48f653c6",
		Sequence: 16452784,
		UnifiedOutput: mtg.UnifiedOutput{
			AppId: "bdee2414-045b-31b7-b8a7-7998b36f5c93",
		},
	}
	ba = &mtg.Action{
		OutputId: "b823b036-0c6a-35fb-8823-291f4f563a0d",
		Sequence: 16452833,
		UnifiedOutput: mtg.UnifiedOutput{
			AppId: "bdee2414-045b-31b7-b8a7-7998b36f5c93",
		},
	}
)

func mtgFixAction(ctx context.Context, store *mtg.SQLite3Store, a *mtg.Action, ts string) {
	b, _ := common.Base91Decode(ts)
	txs, _ := mtg.DeserializeTransactions(b)
	txs[0].AppId = a.AppId
	txs[0].Sequence = a.Sequence
	err := store.FinishAction(ctx, a.OutputId, mtg.ActionStateDone, txs)
	if err != nil {
		panic(err)
	}
}

func signerFix(ctx context.Context, path string) {
	db, err := common.OpenSQLite3Store(path, signer.SCHEMA)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	key := "FIX:3db5263a878192bbf6525a41ffc743d9deb330b8"
	row := db.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&key)
	if err == sql.ErrNoRows {
	} else if err != nil {
		panic(err)
	} else {
		return
	}

	txn, err := db.BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}
	defer txn.Rollback()

	cols := []string{"output_id", "compaction", "transactions", "session_id", "created_at"}
	vals := []any{"fefc4470-7e29-3a30-8c65-a92f48f653c6", "", fixA, "3efd5229-a6bc-3417-82fd-be96982ee8a5", time.Now().UTC()}
	_, err = txn.ExecContext(ctx, buildInsertionSQL("action_results", cols), vals...)
	if err != nil {
		panic(err)
	}
	vals = []any{"b823b036-0c6a-35fb-8823-291f4f563a0d", "", fixB, "d8321fb5-f42e-3bfb-965b-e10b7862e858", time.Now().UTC()}
	_, err = txn.ExecContext(ctx, buildInsertionSQL("action_results", cols), vals...)
	if err != nil {
		panic(err)
	}
	_, err = txn.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)",
		key, "action_results", time.Now().UTC())
	if err != nil {
		panic(err)
	}

	err = txn.Commit()
	if err != nil {
		panic(err)
	}
}

func buildInsertionSQL(table string, cols []string) string {
	vals := strings.Repeat("?, ", len(cols))
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ","), vals[:len(vals)-2])
}

func SignerBootCmd(c *cli.Context) error {
	ctx := context.Background()

	version := c.App.Metadata["VERSION"].(string)
	ua := fmt.Sprintf("Mixin Safe Signer (%s)", version)
	resty := mixin.GetRestyClient()
	resty.SetTimeout(time.Second * 30)
	resty.SetHeader("User-Agent", ua)

	mc, err := config.ReadConfiguration(c.String("config"), "signer")
	if err != nil {
		return err
	}
	mc.Signer.MTG.GroupSize = 1
	mc.Signer.MTG.LoopWaitDuration = int64(time.Second)

	signerFix(ctx, mc.Signer.StoreDir+"/mpc.sqlite3")
	mtgFix(ctx, mc.Signer.StoreDir+"/mtg.sqlite3")

	db, err := mtg.OpenSQLite3Store(mc.Signer.StoreDir + "/mtg.sqlite3")
	if err != nil {
		return err
	}
	defer db.Close()
	mtgFixAction(ctx, db, aa, fixA)
	mtgFixAction(ctx, db, ba, fixB)
	group, err := mtg.BuildGroup(ctx, db, mc.Signer.MTG)
	if err != nil {
		return err
	}
	group.EnableDebug()

	messenger, err := messenger.NewMixinMessenger(ctx, mc.Signer.Messenger())
	if err != nil {
		return err
	}

	kd, err := signer.OpenSQLite3Store(mc.Signer.StoreDir + "/mpc.sqlite3")
	if err != nil {
		return err
	}
	defer kd.Close()

	s := &mixin.Keystore{
		ClientID:          mc.Signer.MTG.App.AppId,
		SessionID:         mc.Signer.MTG.App.SessionId,
		SessionPrivateKey: mc.Signer.MTG.App.SessionPrivateKey,
		ServerPublicKey:   mc.Signer.MTG.App.ServerPublicKey,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	me, err := client.UserMe(ctx)
	if err != nil {
		return err
	}
	key, err := mixinnet.ParseKeyWithPub(mc.Signer.MTG.App.SpendPrivateKey, me.SpendPublicKey)
	if err != nil {
		return err
	}
	mc.Signer.MTG.App.SpendPrivateKey = key.String()

	node := signer.NewNode(kd, group, messenger, mc.Signer, mc.Keeper.MTG, client)
	node.Boot(ctx)

	if mmc := mc.Signer.MonitorConversaionId; mmc != "" {
		go MonitorSigner(ctx, db, kd, mc.Signer, group, mmc, version)
	}

	group.AttachWorker(mc.Signer.AppId, node)
	group.Run(ctx)
	return nil
}

func SignerFundRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"), "signer")
	if err != nil {
		return err
	}
	op := &common.Operation{
		Type:  common.OperationTypeWrapper,
		Id:    uuid.Must(uuid.NewV4()).String(),
		Curve: common.CurveSecp256k1ECDSABitcoin,
	}
	return makeSignerPaymentRequest(mc.Signer, op, mc.Signer.AssetId, decimal.NewFromInt(1000000))
}

func SignerKeygenRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"), "signer")
	if err != nil {
		return err
	}
	op := &common.Operation{
		Type:  common.OperationTypeKeygenInput,
		Id:    c.String("session"),
		Curve: byte(c.Uint("curve")),
	}
	return makeSignerPaymentRequest(mc.Signer, op, mc.Signer.KeeperAssetId, decimal.NewFromInt(10))
}

func SignerSignRequest(c *cli.Context) error {
	mc, err := config.ReadConfiguration(c.String("config"), "signer")
	if err != nil {
		return err
	}
	op := &common.Operation{
		Type:   common.OperationTypeSignInput,
		Id:     c.String("session"),
		Curve:  byte(c.Uint("curve")),
		Public: hex.EncodeToString(common.Fingerprint(c.String("key"))),
		Extra:  []byte(c.String("msg")),
	}
	if op.Curve == common.CurveEdwards25519Mixin {
		mask, err := crypto.KeyFromString(c.String("mask"))
		if err != nil || !mask.CheckKey() {
			return fmt.Errorf("mixin mask %s %v", c.String("mask"), err)
		}
		op.Extra = binary.BigEndian.AppendUint16(mask[:], uint16(c.Int("index")))
		op.Extra = append(op.Extra, c.String("msg")...)
	}
	return makeSignerPaymentRequest(mc.Signer, op, mc.Signer.KeeperAssetId, decimal.NewFromInt(10))
}

func makeSignerPaymentRequest(conf *signer.Configuration, op *common.Operation, assetId string, amount decimal.Decimal) error {
	ctx := context.Background()
	aesKey := common.ECDHEd25519(conf.SharedKey, conf.KeeperPublicKey)

	s := &mixin.Keystore{
		ClientID:          conf.MTG.App.AppId,
		SessionID:         conf.MTG.App.SessionId,
		SessionPrivateKey: conf.MTG.App.SessionPrivateKey,
		ServerPublicKey:   conf.MTG.App.ServerPublicKey,
	}
	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return err
	}
	_, err = client.UserMe(ctx)
	if err != nil {
		return err
	}

	switch op.Curve {
	case common.CurveSecp256k1ECDSABitcoin:
	case common.CurveSecp256k1ECDSAEthereum:
	case common.CurveSecp256k1SchnorrBitcoin:
	case common.CurveEdwards25519Default:
	case common.CurveEdwards25519Mixin:
	default:
		return fmt.Errorf("CurveSecp256k1ECDSABitcoin:\t\t%d\nCurveSecp256k1SchnorrBitcoin:\t\t%d\nCurveEdwards25519Default:\t%d\nCurveEdwards25519Mixin:\t\t%d\n",
			common.CurveSecp256k1ECDSABitcoin, common.CurveSecp256k1SchnorrBitcoin, common.CurveEdwards25519Default, common.CurveEdwards25519Mixin)
	}

	extra := common.AESEncrypt(aesKey[:], op.Encode(), op.Id)
	input := mixin.TransferInput{
		AssetID: assetId,
		Amount:  amount,
		TraceID: op.Id,
	}
	input.OpponentMultisig.Receivers = conf.MTG.Genesis.Members
	input.OpponentMultisig.Threshold = uint8(conf.MTG.Genesis.Threshold)
	input.Memo = mtg.EncodeMixinExtraBase64(conf.AppId, extra)
	pay, err := client.VerifyPayment(ctx, input)
	if err != nil {
		return err
	}
	url := "mixin://codes/" + pay.CodeID
	fmt.Println(url)
	qrterminal.GenerateHalfBlock(url, qrterminal.H, os.Stdout)
	return nil
}

// FIXME remove these
const fixA = ":CoABAUc{II2g{F/_N<1%o&oKHBAIAAAAAAAAAAAAAAAAAAAlB:z0YH%b`OaPS1uWSu{pD*BuW~9f^Qx+A#*lEFUKs1~(BtP@@lT!7-1XmWMbRT*-u`jeMta[,>G{Hg0jC{Q{+obc,dd:0D?-a@inDeff):0Z!j/,,`jcD+,%kWMQJIw)P{iNP#EH*2G/!uxFk7RMllE:mf;PJ^=08vifMabajeME2_y5Ywi&G?Eaj1XLRf0>*[P02Ab.fZdoR1#YEBSRlwbCi|RFK30`YFTji_,A._iR2KwX6@iUz}Dcj&Y{HxxO[[PhMSbKmCSB#d?{a3PB2!xml+G)2m@~*Vj*4*E[h4GbRs@sYLT:4kfWoYu~!V<#jVjv!AbNkd;:IRzv6fS6t^aE*5Xs1a0VkKU;L.xg)SC}Rj/KCAS4Oef^feMwJ<#bv`jLl61S*k:#J`ywPGTCJAJ**4)g2=:px7jkD-DwncM{H4+oE]PowMf,foM?1@+|,hRd%/IJf.G<!)1JkAkMz+x7ntX/!s<sYBRjw~wF*LTIRH)vvWia%k,cjDTAJf0z6aRLuQb#k2oJ!B?q6gSMz~Ibj[j;Iq@A.bjR%Qbcjaec!3#xNrT7lJ.R*b;HR2+66_j;LOfq+-ioR-1wvkTmDCbWmie~H.xFk|P1tAb.f(Xs13#5*mSO8cfR*Ye7Io!UkbR4t{xvnLdYRd?-uKU.LtaH*OC{Hs*,,BRWzV<[hmM/Hxx)Pxi2t(a@hDT_2j/KC2jB)CFF*tX7I9=u6hRVztEml3zIRu<@@FT!lV<Vof;Q27=m6vi@+Ef#k0o7IV<|j%RD2`EToLT8!}uQv[P~1cf,f,z~!z#,,QUQl1E:mMSJ3<:_@lThiF<g)Sup!2+sYgSV%}D+*iM-0Pzgv|PCJD.h)5X?1MwmN3Pe5x.[hHT/!j/mCBS*4V<2+4G<!d0u*LT97exxlQuB2]=RN;TSz>x]hg:#Jm/88fS<LKbf)LTM!~,tNWjB2^aUo;HIRGwPC*T/4x.,f1prI0#Ek1jKl`EllU:o!,xTCBSo,obxn**XR30VkrTl,rawnBT{H_yUv|PYz5I.f,HjJt<!62igD4xHf:081iw[YFTzO7IWotX}RQzWN7jiws,LmWCYR^=MkVjN8@Dt)uM8!%@y6Pi<4Yb#kgMp!8u0P|QB)y1goceYRc?GmrTyOf<q+Qu;I1#V[1jNl1EKmS:Y!m/!6JUOGCbMk*H!I)1ex_jkDFyA.*z{Hd0Yv|P]+cf/flNB#<#PvgS@DB2[h@Gh2R!-a%R>49E;m4GFK{yAv*Tc%raR,@0{HX<A.wioRKbNk1p+H.xZEbReMib-jVv%2j/7P2jLGAJxn?RbRd?A.gS-IWfKm@QCt_)Bt-Vm16w7qxo@(2}io_`Q1D{#gqM?qo2*jq<IX7?P.C~`gVY6#bCG=wN2wa<Ct~LX.O:MsM[J{%kN/wuuJQ!~U4F8u}$6eA:[+Q!F6Ou&5t^!J:8+gdM>%xvkKK(izQQ9aaaFHyTshz1kDSCgvhyqKG]sk+%<LA%BZ9OxX!Eu.GP*/3AAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAA"
const fixB = ":C|(BA4IEMwbX)[KWqO}DhM;42dAQAAAAAAAAAAAAAAAAAAA:C3NOxMo1@d0ekNDtk-]^GvDBt`h9<fIyB$I8RU@m{Z}~G~9p18=!6`jB#~wR*+G{H(1ex|PuRqb,fhdzJ,(%N+TQPabUfIu}Rux&NbjcDWfH*tXIR)1WNBR?4~w$kcMB#*x18+SWGlaP,ASU23+u66RV%cf#k1pZ!GwixLTMzexMk9XuIJw^arTLzdEt)ddjJ2#WmASOlIb+*a:HRE.&6JUHu<,Uoie(JV<vv6R}R$x%kmM-0vx=Y[PTz[I.fKS022#px+Sn!J.A.Vv.Rn!Ak$S97Ib{m5z@J`yAvFTxtraR*?z{Ht<Tv1j|+CF[,@i,0^yD+ASz2Ufaj$YE2j/uC7RLGvE]hLd_2p@bvLThD;I?,rXrIA.q6bj6lexKmb;PJ(1r6vi)Gyb/m#XM!Y<IkAk}InEklfd.R202N|PI)Wx,fkM.R3#%NwiKl+xnjrN.Rs*V[VjiiQbb,}ik2-1tYFT2)}DQ,[j{HF)tN[PQGv<g)WCFK}uK[xPWzN<AkddU2P*oE$S*4h.h)Au<1n/sY`jPzy1cj,z}RSz%@$SUzMfS*k:Q2[=08fS%GOff)cMx2#1cv2i.L}x+*^jIK3=9NGS|!sf_fLTU2<#aCASOl`E]hk:qI$/08Vj#GGf3i%*@2S*mC*TG)raG*Tv{Hq@Pv|PXG7I,f?HIRH)_Y@i0t!xTfKSB#MwfC{QutN<7ntXrIg0-BLUOG-D3i4oB2r*@YAS77jai)|js1X<$8?i`+cf#kyo81GwqNRi*4Z.3i>i<1?+Ik*T:+t<2+=H!I1#?jVjKlIb[,U:HR(@!6fSV%x.gobd818=nvPiiD,E,*eM{Hm/@@[PBJwx^f6YjJ=#IkGSmDvEojuM#1m!ZxKU0td<P,tX$JE.-u@ifMtab,Xd~Hv<66bRO89ECkzp,0b?)YlT3tgb/m3X5!j/fvmScDv<s)?RB2{yBk7R?+cfg)UM!ID?PvKUMld<]hW:Q2d0n6)T37;a)*JT>IE.#P+TN)~IE*ie_2]=zP]PJ)F<,f7X>I=#BZwiNlMfxl^j%2iwmNmSciUf4irNzJV<W62i{+}D@,8Y-000qN[Pt!~IF*1px2^yx8xP^DFy2+:0R28ucvFT*4mx**4Gc!;(~BRil,UfG*PvZ!]=S6bj:L#Edja:@2f0z6fSm!(aE*5X%2m@4YGSv2Ef&i{ibR#12NQU|RCb/fVdDJ=#xNWjSl61A.d;6In/vPAkztwbll&)|R?+jv$SZ%raUo(X~HF?R[[P#Ouf/f{i}RLw+*mSz2d<IfLTLRR*dxrT{1[I<mtX5!g0tYAkM)s,R*Tv}Ro/|j{in!w(EA<vw(Y!u`<fE&gkI1:DyX$YAO%-i#!BH,LU4X$KcIn6$Wn9w4y0&2YSJE?[nt`,}dD8jRC*=JB)f|0zH%yy]!S`POVErlP5Bu[|*yYX%^HvsY_RD`Q%1@~okYoDl5|1ePth#7uR,;K-:7%MtT2!Jmfs>R4[Dk9g6CLXQ6Ba!(1k_jk6#OAAAAAAAAAAAAAA:CAAAAAAAAAAAAAAAAAAA"
