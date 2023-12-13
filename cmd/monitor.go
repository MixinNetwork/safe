package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/MixinNetwork/bot-api-go-client"
	"github.com/MixinNetwork/mixin/logger"
	nstore "github.com/MixinNetwork/nfo/store"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	kstore "github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/safe/signer"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/shopspring/decimal"
)

type UserStore interface {
	ReadProperty(ctx context.Context, k string) (string, error)
	WriteProperty(ctx context.Context, k, v string) error
}

func MonitorSigner(ctx context.Context, mdb *nstore.BadgerStore, store *signer.SQLite3Store, conf *signer.Configuration, group *mtg.Group, conversationId string) {
	logger.Printf("MonitorSigner(%s, %s)", group.GenesisId(), conversationId)
	startedAt := time.Now()

	app := conf.MTG.App
	path := fmt.Sprintf("/conversations/%s", conversationId)
	accessToken, err := bot.SignAuthenticationToken(app.ClientId, app.SessionId, app.PrivateKey, "GET", path, "")
	if err != nil {
		panic(err)
	}
	conv, err := bot.ConversationShow(ctx, conversationId, accessToken)
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(3 * time.Minute)
		msg, err := bundleSignerState(ctx, mdb, store, conf, group, startedAt)
		if err != nil {
			logger.Verbosef("Monitor.bundleSignerState() => %v", err)
			continue
		}
		postMessages(ctx, store, conv, conf.MTG, msg)
		time.Sleep(30 * time.Minute)
	}
}

func bundleSignerState(ctx context.Context, mdb *nstore.BadgerStore, store *signer.SQLite3Store, conf *signer.Configuration, grp *mtg.Group, startedAt time.Time) (string, error) {
	state := "👩‍⚖️ 🧑‍⚖️ 👨‍⚖️ Signer 👩‍⚖️ 🧑‍⚖️ 👨‍⚖️\n"
	state = state + fmt.Sprintf("⏲️ Run time :%s\n", time.Now().Sub(startedAt).String())
	state = state + fmt.Sprintf("⏲️ Group: %s %d\n", mixin.HashMembers(grp.GetMembers()), grp.GetThreshold())

	tl, err := mdb.ListTransactions(mtg.TransactionStateInitial, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Initial Transactions: %d\n", len(tl))
	tl, err = mdb.ListTransactions(mtg.TransactionStateSigning, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Signing Transactions: %d\n", len(tl))
	tl, err = mdb.ListTransactions(mtg.TransactionStateSigned, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Signed Transactions: %d\n", len(tl))

	ol, err := mdb.ListOutputsForAsset("", mixin.UTXOStateUnspent, conf.KeeperAssetId, 10)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 MSKT Outputs: %d\n", len(ol))
	sa, err := fetchAsset(ctx, conf.MTG, conf.AssetId)
	if err != nil {
		return "", err
	}
	tTredecillion := decimal.New(10, 12+42)
	amount := decimal.RequireFromString(sa.Balance).Div(tTredecillion).IntPart()
	state = state + fmt.Sprintf("💍 MSST Balance: %d TT\n", amount)

	ss, err := store.SessionsState(ctx)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Initial sessions: %d\n", ss.Initial)
	state = state + fmt.Sprintf("🔑 Pending sessions: %d\n", ss.Pending)
	state = state + fmt.Sprintf("🔑 Final sessions: %d\n", ss.Done)
	state = state + fmt.Sprintf("🔑 Generated keys: %d\n", ss.Keys)

	state = state + fmt.Sprintf("🦷 Binary version: %s", config.AppVersion)
	return state, nil
}

func MonitorKeeper(ctx context.Context, mdb *nstore.BadgerStore, store *kstore.SQLite3Store, conf *keeper.Configuration, group *mtg.Group, conversationId string) {
	logger.Printf("MonitorKeeper(%s, %s)", group.GenesisId(), conversationId)
	startedAt := time.Now()

	app := conf.MTG.App
	path := fmt.Sprintf("/conversations/%s", conversationId)
	accessToken, err := bot.SignAuthenticationToken(app.ClientId, app.SessionId, app.PrivateKey, "GET", path, "")
	if err != nil {
		panic(err)
	}
	conv, err := bot.ConversationShow(ctx, conversationId, accessToken)
	if err != nil {
		panic(err)
	}

	for {
		time.Sleep(3 * time.Minute)
		msg, err := bundleKeeperState(ctx, mdb, store, conf, group, startedAt)
		if err != nil {
			logger.Verbosef("Monitor.bundleKeeperState() => %v", err)
			continue
		}
		postMessages(ctx, store, conv, conf.MTG, msg)
		time.Sleep(30 * time.Minute)
	}
}

func bundleKeeperState(ctx context.Context, mdb *nstore.BadgerStore, store *kstore.SQLite3Store, conf *keeper.Configuration, grp *mtg.Group, startedAt time.Time) (string, error) {
	state := "👮‍♀️ 👮 👮‍♂️ Keeper 👮‍♀️ 👮 👮‍♂️\n"
	state = state + fmt.Sprintf("⏲️ Run time :%s\n", time.Now().Sub(startedAt).String())
	state = state + fmt.Sprintf("⏲️ Group: %s %d\n", mixin.HashMembers(grp.GetMembers()), grp.GetThreshold())

	req, err := store.ReadLatestRequest(ctx)
	if err != nil {
		return "", err
	} else if req != nil {
		state = state + fmt.Sprintf("🎆 Latest request: %s\n", req.MixinHash)
	}
	info, err := store.ReadLatestNetworkInfo(ctx, keeper.SafeChainBitcoin, time.Now())
	if err != nil {
		return "", err
	} else if info != nil {
		state = state + fmt.Sprintf("🚴 Bitcoin height: %d\n", info.Height)
	}

	tl, err := mdb.ListTransactions(mtg.TransactionStateInitial, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Initial Transactions: %d\n", len(tl))
	tl, err = mdb.ListTransactions(mtg.TransactionStateSigning, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Signing Transactions: %d\n", len(tl))
	tl, err = mdb.ListTransactions(mtg.TransactionStateSigned, 1000)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🫰 Signed Transactions: %d\n", len(tl))

	ol, err := mdb.ListOutputsForAsset("", mixin.UTXOStateUnspent, mtg.StorageAssetId, 10)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 XIN Outputs: %d\n", len(ol))
	ol, err = mdb.ListOutputsForAsset("", mixin.UTXOStateUnspent, conf.AssetId, 10)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("💍 MSKT Outputs: %d\n", len(ol))

	sc, err := store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleSigner)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Signer keys: %d\n", sc)
	oc, err := store.CountSpareKeys(ctx, common.CurveSecp256k1ECDSABitcoin, common.RequestFlagNone, common.RequestRoleObserver)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🔑 Observer keys: %d\n", oc)

	state = state + fmt.Sprintf("🦷 Binary version: %s", config.AppVersion)
	return state, nil
}

func postMessages(ctx context.Context, store UserStore, conv *bot.Conversation, conf *mtg.Configuration, msg string) {
	app := conf.App
	var messages []*bot.MessageRequest
	for i := range conv.Participants {
		s := conv.Participants[i]
		if s.UserId == app.ClientId {
			continue
		}
		u, err := fetchConversationUser(ctx, store, s.UserId, conf)
		if err != nil || checkBot(u) {
			logger.Verbosef("Monitor.fetchConversationUser(%s) => %v %v", s.UserId, u, err)
			continue
		}
		messages = append(messages, &bot.MessageRequest{
			ConversationId: conv.ConversationId,
			RecipientId:    s.UserId,
			Category:       bot.MessageCategoryPlainText,
			MessageId:      common.UniqueId(msg, s.UserId),
			Data:           base64.RawURLEncoding.EncodeToString([]byte(msg)),
		})
	}
	err := bot.PostMessages(ctx, messages, app.ClientId, app.SessionId, app.PrivateKey)
	logger.Verbosef("Monitor.PostMessages(\n%s) => %d %v", msg, len(messages), err)
}

func fetchAsset(ctx context.Context, conf *mtg.Configuration, assetId string) (*bot.Asset, error) {
	app := conf.App
	token, err := bot.SignAuthenticationToken(app.ClientId, app.SessionId, app.PrivateKey, "GET", "/assets/"+assetId, "")
	if err != nil {
		return nil, err
	}
	return bot.AssetShow(ctx, assetId, token)
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

	u, err := bot.GetUser(ctx, id, app.ClientId, app.SessionId, app.PrivateKey)
	if err != nil || u == nil {
		return nil, err
	}
	val = string(common.MarshalJSONOrPanic(u))
	err = store.WriteProperty(ctx, key, val)
	return u, err
}

func checkBot(u *bot.User) bool {
	id, err := strconv.ParseInt(u.IdentityNumber, 10, 64)
	if err != nil {
		panic(u.IdentityNumber)
	}
	return id > 7000000000
}
