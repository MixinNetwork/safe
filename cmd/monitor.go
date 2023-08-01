package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/MixinNetwork/bot-api-go-client"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/config"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go"
)

func MonitorKeeper(ctx context.Context, store *store.SQLite3Store, conf *mtg.Configuration, conversationId string) {
	startedAt := time.Now()

	path := fmt.Sprintf("/conversations/%s", conversationId)
	accessToken, err := bot.SignAuthenticationToken(conf.App.ClientId, conf.App.SessionId, conf.App.PrivateKey, "GET", path, "")
	if err != nil {
		panic(err)
	}
	conv, err := bot.ConversationShow(ctx, conversationId, accessToken)
	if err != nil {
		panic(err)
	}

	for {
		msg, err := bundleKeeperState(ctx, store, startedAt)
		if err != nil {
			logger.Verbosef("Monitor.bundleKeeperState() => %v", err)
			continue
		}
		var messages []*bot.MessageRequest
		for i := range conv.Participants {
			s := conv.ParticipantSessions[i]
			if s.UserId == conf.App.ClientId {
				continue
			}
			messages = append(messages, &bot.MessageRequest{
				ConversationId: conversationId,
				RecipientId:    s.UserId,
				Category:       bot.MessageCategoryPlainText,
				MessageId:      mixin.UniqueConversationID(msg, s.SessionId),
				Data:           base64.RawURLEncoding.EncodeToString([]byte(msg)),
			})
		}
		err = bot.PostMessages(ctx, messages, conf.App.ClientId, conf.App.SessionId, conf.App.PrivateKey)
		logger.Verbosef("Monitor.PostMessages(\n%s) => %d %v", msg, len(messages), err)
		time.Sleep(30 * time.Minute)
	}
}

func bundleKeeperState(ctx context.Context, store *store.SQLite3Store, startedAt time.Time) (string, error) {
	state := fmt.Sprintf("⏲️ Run time :%s\n", time.Now().Sub(startedAt).String())
	req, err := store.ReadLatestRequest(ctx)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🎆 Latest request: %s\n", req.MixinHash)
	info, err := store.ReadLatestNetworkInfo(ctx, keeper.SafeChainBitcoin)
	if err != nil {
		return "", err
	}
	state = state + fmt.Sprintf("🚴 Bitcoin height: %d\n", info.Height)
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
