package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	kstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/fox-one/mixin-sdk-go/v2/mixinnet"
)

type UserStore interface {
	ReadProperty(ctx context.Context, k string) (string, error)
	WriteProperty(ctx context.Context, k, v string) error
}

func MonitorSigner(ctx context.Context, mdb *mtg.SQLite3Store, store *signer.SQLite3Store, conf *signer.Configuration, group *mtg.Group, conversationId, version string) {
	logger.Printf("MonitorSigner(%s, %s)", group.GenesisId(), conversationId)
	startedAt := time.Now()

	app := conf.MTG.App
	conv, err := bot.ConversationShow(ctx, conversationId, &bot.SafeUser{
		UserId:            app.AppId,
		SessionId:         app.SessionId,
		SessionPrivateKey: app.SessionPrivateKey,
	})
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(1 * time.Minute)
		msg, err := bundleSignerState(ctx, mdb, store, conf, group, startedAt, version)
		if err != nil {
			logger.Verbosef("Monitor.bundleSignerState() => %v", err)
			continue
		}
		postMessages(ctx, store, conv, conf.MTG, msg, conf.ObserverUserId)
		time.Sleep(30 * time.Minute)
	}
}

func bundleSignerState(ctx context.Context, mdb *mtg.SQLite3Store, store *signer.SQLite3Store, conf *signer.Configuration, grp *mtg.Group, startedAt time.Time, version string) (string, error) {
	state := "📋📋📋📋📋 Signer 📋📋📋📋📋\n"
	state = state + fmt.Sprintf("⏲️ Run time: %s\n", time.Since(startedAt).String())
	state = state + fmt.Sprintf("⏲️ Group: %s 𝕋%d\n", mixinnet.HashMembers(grp.GetMembers())[:16], grp.GetThreshold())

	state = state + "\n𝗠𝙏𝗚\n"
	tl, _, err := mdb.ListTransactions(ctx, mtg.TransactionStateInitial, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Initial Transactions: %d\n", len(tl))
	tl, _, err = mdb.ListTransactions(ctx, mtg.TransactionStateSigned, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Signed Transactions: %d\n", len(tl))
	tl, _, err = mdb.ListTransactions(ctx, mtg.TransactionStateSnapshot, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Snapshot Transactions: %d\n", len(tl))

	ol, err := mdb.ListOutputsForAsset(ctx, conf.AppId, conf.KeeperAssetId, 0, math.MaxInt64, mixin.UTXOStateUnspent, 10)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 MSKT Outputs: %d\n", len(ol))

	app := conf.MTG.App
	hash := bot.HashMembers([]string{app.AppId})
	msst := crypto.Sha256Hash([]byte(conf.AssetId))
	sol, err := bot.ListUnspentOutputs(ctx, hash, 1, msst.String(), &bot.SafeUser{
		UserId:            app.AppId,
		SessionId:         app.SessionId,
		SessionPrivateKey: app.SessionPrivateKey,
	})
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 MSST Outputs: %d\n", len(sol))

	state = state + "\n𝗔𝙋𝗣\n"
	ss, err := store.SessionsState(ctx)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Initial sessions: %d\n", ss.Initial)
	state = state + fmt.Sprintf("🔑 Pending sessions: %d\n", ss.Pending)
	state = state + fmt.Sprintf("🔑 Final sessions: %d\n", ss.Done)
	state = state + fmt.Sprintf("🔑 Generated keys: %d\n", ss.Keys)

	state = state + fmt.Sprintf("🦷 Binary version: %s", version)
	return state, nil
}

func MonitorKeeper(ctx context.Context, mdb *mtg.SQLite3Store, store *kstore.SQLite3Store, conf *keeper.Configuration, group *mtg.Group, conversationId, version string) {
	logger.Printf("MonitorKeeper(%s, %s)", group.GenesisId(), conversationId)
	startedAt := time.Now()

	app := conf.MTG.App
	conv, err := bot.ConversationShow(ctx, conversationId, &bot.SafeUser{
		UserId:            app.AppId,
		SessionId:         app.SessionId,
		SessionPrivateKey: app.SessionPrivateKey,
	})
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(1 * time.Minute)
		msg, err := bundleKeeperState(ctx, mdb, store, conf, group, startedAt, version)
		if err != nil {
			logger.Verbosef("Monitor.bundleKeeperState() => %v", err)
			continue
		}
		postMessages(ctx, store, conv, conf.MTG, msg, conf.ObserverUserId)
		time.Sleep(30 * time.Minute)
	}
}

func bundleKeeperState(ctx context.Context, mdb *mtg.SQLite3Store, store *kstore.SQLite3Store, conf *keeper.Configuration, grp *mtg.Group, startedAt time.Time, version string) (string, error) {
	state := "🧱🧱🧱🧱🧱 Keeper 🧱🧱🧱🧱🧱\n"
	state = state + fmt.Sprintf("⏲️ Run time: %s\n", time.Since(startedAt).String())
	state = state + fmt.Sprintf("⏲️ Group: %s 𝕋%d\n", mixinnet.HashMembers(grp.GetMembers())[:16], grp.GetThreshold())

	state = state + "\n𝗠𝙏𝗚\n"
	req, err := store.ReadLatestRequest(ctx)
	if err != nil {
		return "", err
	} else if req != nil {
		state = state + fmt.Sprintf("🎆 Latest request: %x\n", req.MixinHash[:8])
	}
	info, err := store.ReadLatestNetworkInfo(ctx, common.SafeChainBitcoin, time.Now())
	if err != nil {
		return "", err
	} else if info != nil {
		state = state + fmt.Sprintf("🚴 Bitcoin height: %d\n", info.Height)
	}

	tl, _, err := mdb.ListTransactions(ctx, mtg.TransactionStateInitial, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Initial Transactions: %d\n", len(tl))
	tl, _, err = mdb.ListTransactions(ctx, mtg.TransactionStateSigned, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Signed Transactions: %d\n", len(tl))
	tl, _, err = mdb.ListTransactions(ctx, mtg.TransactionStateSnapshot, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Snapshot Transactions: %d\n", len(tl))

	ol, err := mdb.ListOutputsForAsset(ctx, conf.AppId, mtg.StorageAssetId, 0, math.MaxInt64, mixin.UTXOStateUnspent, 10)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 XIN Outputs: %d\n", len(ol))
	ol, err = mdb.ListOutputsForAsset(ctx, conf.AppId, conf.AssetId, 0, math.MaxInt64, mixin.UTXOStateUnspent, 10)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 MSKT Outputs: %d\n", len(ol))

	state = state + "\n𝗔𝙋𝗣\n"
	sbc, err := store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleSigner)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Signer Bitcoin keys: %d\n", sbc)
	sec, err := store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSAEthereum, common.RequestFlagNone, common.RequestRoleSigner)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Signer Ethereum keys: %d\n", sec)

	obc, err := store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleObserver)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Observer Bitcoin keys: %d\n", obc)
	oec, err := store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSAEthereum, common.RequestFlagNone, common.RequestRoleObserver)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Observer Ethereum keys: %d\n", oec)

	tc, err := store.CountTransactionsByState(ctx, common.RequestStateInitial)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💷 Initial Transactions: %d\n", tc)
	tc, err = store.CountTransactionsByState(ctx, common.RequestStatePending)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💶 Pending Transactions: %d\n", tc)
	tc, err = store.CountTransactionsByState(ctx, common.RequestStateDone)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💵 Done Transactions: %d\n", tc)
	tc, err = store.CountTransactionsByState(ctx, common.RequestStateFailed)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💸 Failed Transactions: %d\n", tc)

	state = state + fmt.Sprintf("🦷 Binary version: %s", version)
	return state, nil
}

func postMessages(ctx context.Context, store UserStore, conv *bot.Conversation, conf *mtg.Configuration, msg, observer string) {
	app := conf.App
	var messages []*bot.MessageRequest
	for i := range conv.Participants {
		s := conv.Participants[i]
		if s.UserId == app.AppId {
			continue
		}
		u, err := fetchConversationUser(ctx, store, s.UserId, conf)
		if err != nil || checkBot(u, observer) {
			logger.Verbosef("Monitor.fetchConversationUser(%s) => %v %v", s.UserId, u, err)
			continue
		}
		messages = append(messages, &bot.MessageRequest{
			ConversationId: conv.ConversationId,
			RecipientId:    s.UserId,
			Category:       bot.MessageCategoryPlainText,
			MessageId:      common.UniqueId(msg, s.UserId),
			DataBase64:     base64.RawURLEncoding.EncodeToString([]byte(msg)),
		})
	}
	err := bot.PostMessages(ctx, messages, &bot.SafeUser{
		UserId:            app.AppId,
		SessionId:         app.SessionId,
		SessionPrivateKey: app.SessionPrivateKey,
	})
	logger.Verbosef("Monitor.PostMessages(\n%s) => %d %v", msg, len(messages), err)
}

func fetchConversationUser(ctx context.Context, store UserStore, id string, conf *mtg.Configuration) (*bot.User, error) {
	app := conf.App
	key := fmt.Sprintf("MONITOR:USER:%s", id)
	val, err := store.ReadProperty(ctx, key)
	if err != nil {
		return nil, err
	}
	if val != "" {
		var u bot.User
		err = json.Unmarshal([]byte(val), &u)
		return &u, err
	}

	u, err := bot.GetUser(ctx, id, &bot.SafeUser{
		UserId:            app.AppId,
		SessionId:         app.SessionId,
		SessionPrivateKey: app.SessionPrivateKey,
	})
	if err != nil || u == nil {
		return nil, err
	}
	val = string(common.MarshalJSONOrPanic(u))
	err = store.WriteProperty(ctx, key, val)
	return u, err
}

func checkBot(u *bot.User, observer string) bool {
	if u.UserId == observer {
		return false
	}
	id, err := strconv.ParseInt(u.IdentityNumber, 10, 64)
	if err != nil {
		panic(u.IdentityNumber)
	}
	return id > 7000000000
}
