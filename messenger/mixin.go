package messenger

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/gofrs/uuid/v5"
)

type MixinConfiguration struct {
	UserId         string `toml:"user"`
	SessionId      string `toml:"session"`
	Key            string `toml:"key"`
	SendBuffer     int    `toml:"send-buffer"`
	ReceiveBuffer  int    `toml:"receive-buffer"`
	ConversationId string `toml:"conversation"`
}

type MixinMessenger struct {
	client         *mixin.Client
	conf           *MixinConfiguration
	conversationId string
	recv           chan []byte
	send           chan *mixin.MessageRequest
}

type MixinMessage struct {
	Peer      string
	Data      []byte
	CreatedAt time.Time
}

func NewMixinMessenger(ctx context.Context, conf *MixinConfiguration) (*MixinMessenger, error) {
	if conf.SendBuffer >= 100 || conf.SendBuffer == 0 {
		panic(fmt.Errorf("messenger messages limit %d", conf.SendBuffer))
	}

	s := &mixin.Keystore{
		ClientID:          conf.UserId,
		SessionID:         conf.SessionId,
		SessionPrivateKey: conf.Key,
	}

	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return nil, err
	}
	mm := &MixinMessenger{
		client:         client,
		conf:           conf,
		conversationId: conf.ConversationId,
		recv:           make(chan []byte, conf.ReceiveBuffer),
		send:           make(chan *mixin.MessageRequest, conf.SendBuffer),
	}
	go mm.loopReceive(ctx)
	go mm.loopSend(ctx, time.Second, conf.SendBuffer)

	return mm, nil
}

func (mm *MixinMessenger) ReceiveMessage(ctx context.Context) (*MixinMessage, error) {
	select {
	case b := <-mm.recv:
		sender, err := uuid.FromBytes(b[:16])
		if err != nil {
			panic(err)
		}
		msg := &MixinMessage{
			Peer: sender.String(),
			Data: b[24:],
		}
		ts := binary.BigEndian.Uint64(b[16:24])
		msg.CreatedAt = time.Unix(0, int64(ts))
		return msg, nil
	case <-ctx.Done():
		return nil, ErrorDone
	}
}

func (mm *MixinMessenger) BroadcastPlainMessage(ctx context.Context, data string) error {
	msg := &mixin.MessageRequest{
		ConversationID: mm.conversationId,
		Category:       mixin.MessageCategoryPlainText,
		MessageID:      uniqueMessageId("", []byte(data)),
		Data:           base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) BroadcastMessage(ctx context.Context, b []byte) error {
	msg := mm.buildMessage("", b)
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) SendMessage(ctx context.Context, receiver string, b []byte) error {
	msg := mm.buildMessage(receiver, b)
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) QueueMessage(ctx context.Context, receiver string, b []byte) error {
	msg := mm.buildMessage(receiver, b)
	select {
	case mm.send <- msg:
		return nil
	case <-ctx.Done():
		return ErrorDone
	}
}

func (mm *MixinMessenger) buildMessage(receiver string, b []byte) *mixin.MessageRequest {
	data := base64.RawURLEncoding.EncodeToString(b)
	return &mixin.MessageRequest{
		ConversationID: mm.conversationId,
		RecipientID:    receiver,
		Category:       mixin.MessageCategoryPlainText,
		MessageID:      uniqueMessageId(receiver, b),
		Data:           base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
}

func (mm *MixinMessenger) loopReceive(ctx context.Context) {
	for {
		blaze := bot.NewBlazeClient(mm.conf.UserId, mm.conf.SessionId, mm.conf.Key)
		err := blaze.Loop(context.Background(), mm)
		logger.Printf("messenger.loopReceive %v\n", err)
		if ctx.Err() != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
}

func (mm *MixinMessenger) loopSend(ctx context.Context, period time.Duration, size int) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	var batch []*mixin.MessageRequest
	filter := make(map[string]bool)
	for {
		select {
		case msg := <-mm.send:
			if filter[msg.MessageID] {
				continue
			}
			filter[msg.MessageID] = true
			batch = append(batch, msg)
			if len(batch) < size {
				continue
			}
			err := mm.sendMessagesWithoutTimeout(ctx, batch)
			logger.Verbosef("messenger.sendMessagesWithoutTimeout(batch, %d) => %v\n", len(batch), err)
			filter = make(map[string]bool)
			batch = nil
		case <-ticker.C:
			if len(batch) == 0 {
				continue
			}
			err := mm.sendMessagesWithoutTimeout(ctx, batch)
			logger.Verbosef("messenger.sendMessagesWithoutTimeout(ticker, %d) => %v\n", len(batch), err)
			filter = make(map[string]bool)
			batch = nil
		}
	}
}

func (mm *MixinMessenger) OnMessage(ctx context.Context, msg bot.MessageView, userId string) error {
	if msg.Category != mixin.MessageCategoryPlainText {
		return nil
	}
	if msg.ConversationId != mm.conversationId {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil
	}
	data, err = base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return nil
	}
	sender, err := uuid.FromString(msg.UserId)
	if err != nil {
		return nil
	}
	now := uint64(msg.CreatedAt.UnixNano())
	header := binary.BigEndian.AppendUint64(sender.Bytes(), now)
	data = append(header, data...)
	select {
	case mm.recv <- data:
	case <-ctx.Done():
	}
	return nil
}

func (mm *MixinMessenger) OnAckReceipt(ctx context.Context, msg bot.MessageView, userId string) error {
	return nil
}

func (mm *MixinMessenger) SyncAck() bool {
	return true
}

func (mm *MixinMessenger) sendMessagesWithoutTimeout(ctx context.Context, batch []*mixin.MessageRequest) error {
	for {
		err := mm.client.SendMessages(ctx, batch)
		if err != nil && mtg.CheckRetryableError(err) {
			logger.Printf("messenger.sendMessagesWithoutTimeout(retry, %d) => %v", len(batch), err)
			time.Sleep(3 * time.Second)
			continue
		}
		if err != nil && strings.Contains(err.Error(), "413 Request Entity Too Large") && len(batch) >= 2 {
			logger.Printf("messenger.sendMessagesWithoutTimeout(large, %d) => %v", len(batch), err)
			first := batch[:len(batch)/2]
			err = mm.sendMessagesWithoutTimeout(ctx, first)
			if err != nil {
				return err
			}
			second := batch[len(batch)/2:]
			return mm.sendMessagesWithoutTimeout(ctx, second)
		}
		return err
	}
}

func uniqueMessageId(receiver string, b []byte) string {
	s := hex.EncodeToString(b)
	return common.UniqueId(receiver, s)
}
