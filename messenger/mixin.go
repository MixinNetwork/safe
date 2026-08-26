package messenger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
)

const (
	maximumSendBuffer = 100

	encryptedEnvelopeVersion    = byte(1)
	encryptedEnvelopeHeaderSize = 4 + 1 + 4*16
	maximumEncryptedMessageSize = 1 << 20
	maximumRecipientSessions    = 256
	replayCacheSize             = 4096

	encryptedMessagePrefixSize  = 1 + 2 + 32
	encryptedMessageSessionSize = 16 + 48
	encryptedMessageNonceSize   = 12
	encryptedMessageTagSize     = 16
)

var encryptedEnvelopeMagic = [4]byte{'S', 'A', 'F', 'E'}

type MixinConfiguration struct {
	UserId         string `toml:"user"`
	SessionId      string `toml:"session"`
	Key            string `toml:"key"`
	SendBuffer     int    `toml:"send-buffer"`
	ReceiveBuffer  int    `toml:"receive-buffer"`
	ConversationId string `toml:"conversation"`
}

type MixinMessenger struct {
	members               []string
	conf                  *MixinConfiguration
	conversationId        string
	user                  *bot.SafeUser
	sessions              bot.SessionStore
	privateKey            string
	recv                  chan *MixinMessage
	send                  chan *bot.MessageRequest
	postEncryptedMessages func(context.Context, []*bot.MessageRequest) error

	replayMu    sync.Mutex
	replaySeen  map[string]struct{}
	replayOrder []string
	replayNext  int
}

type MixinMessage struct {
	Peer      string
	Data      []byte
	CreatedAt time.Time
}

func NewMixinMessenger(ctx context.Context, conf *MixinConfiguration, members []string) (*MixinMessenger, error) {
	if conf == nil {
		return nil, fmt.Errorf("messenger configuration is nil")
	}
	if conf.SendBuffer <= 0 || conf.SendBuffer >= maximumSendBuffer {
		return nil, fmt.Errorf("messenger messages limit %d", conf.SendBuffer)
	}
	if conf.ReceiveBuffer <= 0 {
		return nil, fmt.Errorf("messenger receive buffer %d", conf.ReceiveBuffer)
	}

	userID, err := canonicalUUID("user", conf.UserId)
	if err != nil {
		return nil, err
	}
	sessionID, err := canonicalUUID("session", conf.SessionId)
	if err != nil {
		return nil, err
	}
	conversationID, err := canonicalUUID("conversation", conf.ConversationId)
	if err != nil {
		return nil, err
	}
	seed, privateKey, err := decodeSessionPrivateKey(conf.Key)
	if err != nil {
		return nil, err
	}

	memberSet := make(map[string]struct{}, len(members))
	normalizedMembers := make([]string, 0, len(members))
	for _, member := range members {
		id, err := canonicalUUID("member", member)
		if err != nil {
			return nil, err
		}
		if _, found := memberSet[id]; found {
			return nil, fmt.Errorf("duplicate messenger member %s", id)
		}
		memberSet[id] = struct{}{}
		normalizedMembers = append(normalizedMembers, id)
	}
	if _, found := memberSet[userID]; !found {
		return nil, fmt.Errorf("messenger user %s is not a member", userID)
	}
	slices.Sort(normalizedMembers)

	normalizedConf := *conf
	normalizedConf.UserId = userID
	normalizedConf.SessionId = sessionID
	normalizedConf.ConversationId = conversationID
	normalizedConf.Key = hex.EncodeToString(seed)

	user := bot.NewSafeUser(userID, sessionID, normalizedConf.Key)
	sessions := bot.NewMapSessionStore()
	mm := &MixinMessenger{
		members:        normalizedMembers,
		conf:           &normalizedConf,
		conversationId: conversationID,
		user:           user,
		sessions:       sessions,
		privateKey:     privateKey,
		recv:           make(chan *MixinMessage, conf.ReceiveBuffer),
		send:           make(chan *bot.MessageRequest, conf.SendBuffer),
		replaySeen:     make(map[string]struct{}),
	}
	mm.postEncryptedMessages = func(ctx context.Context, messages []*bot.MessageRequest) error {
		return bot.PostEncryptedMessages(ctx, messages, sessions, user)
	}

	go mm.loopReceive(ctx)
	go mm.loopSend(ctx, time.Second, conf.SendBuffer)

	return mm, nil
}

func (mm *MixinMessenger) ReceiveMessage(ctx context.Context) (*MixinMessage, error) {
	select {
	case msg := <-mm.recv:
		if msg == nil {
			return nil, ErrorDone
		}
		return msg, nil
	case <-ctx.Done():
		return nil, ErrorDone
	}
}

// BroadcastPlainMessage intentionally sends a server-readable message. Signer
// protocol traffic must use SendMessage, QueueMessage, or BroadcastMessage.
func (mm *MixinMessenger) BroadcastPlainMessage(ctx context.Context, data string) error {
	msg := &bot.MessageRequest{
		ConversationId: mm.conversationId,
		MessageId:      uniqueMessageId("", []byte(data)),
		Category:       bot.MessageCategoryPlainText,
		DataBase64:     base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
	return bot.PostMessageRequest(ctx, msg, mm.user)
}

func (mm *MixinMessenger) BroadcastMessage(ctx context.Context, b []byte) error {
	messages := make([]*bot.MessageRequest, 0, len(mm.members))
	for _, receiver := range mm.members {
		if receiver == mm.conf.UserId {
			continue
		}
		msg, err := mm.buildMessage(receiver, b)
		if err != nil {
			return err
		}
		messages = append(messages, msg)
	}
	return mm.postEncryptedMessages(ctx, messages)
}

func (mm *MixinMessenger) SendMessage(ctx context.Context, receiver string, b []byte) error {
	msg, err := mm.buildMessage(receiver, b)
	if err != nil {
		return err
	}
	return mm.postEncryptedMessages(ctx, []*bot.MessageRequest{msg})
}

func (mm *MixinMessenger) QueueMessage(ctx context.Context, receiver string, b []byte) error {
	msg, err := mm.buildMessage(receiver, b)
	if err != nil {
		return err
	}
	select {
	case mm.send <- msg:
		return nil
	case <-ctx.Done():
		return ErrorDone
	}
}

func (mm *MixinMessenger) buildMessage(receiver string, b []byte) (*bot.MessageRequest, error) {
	receiver, err := canonicalUUID("recipient", receiver)
	if err != nil {
		return nil, err
	}
	if receiver == mm.conf.UserId {
		return nil, fmt.Errorf("messenger recipient is the sender %s", receiver)
	}
	if !slices.Contains(mm.members, receiver) {
		return nil, fmt.Errorf("unknown messenger recipient %s", receiver)
	}
	if len(b) == 0 || len(b) > maximumEncryptedMessageSize-encryptedEnvelopeHeaderSize {
		return nil, fmt.Errorf("invalid messenger payload size %d", len(b))
	}

	messageID := uniqueMessageId(receiver, b)
	envelope, err := marshalEncryptedEnvelope(
		mm.conf.UserId,
		receiver,
		mm.conversationId,
		messageID,
		b,
	)
	if err != nil {
		return nil, err
	}
	return &bot.MessageRequest{
		ConversationId: mm.conversationId,
		RecipientId:    receiver,
		MessageId:      messageID,
		Category:       bot.MessageCategoryEncryptedData,
		DataBase64:     base64.RawURLEncoding.EncodeToString(envelope),
	}, nil
}

func (mm *MixinMessenger) loopReceive(ctx context.Context) {
	for ctx.Err() == nil {
		blaze := bot.NewBlazeClientWithSafeUser(mm.user)
		err := blaze.Loop(ctx, mm)
		logger.Printf("messenger.loopReceive %v\n", err)
		if !waitForMessengerRetry(ctx, 3*time.Second) {
			return
		}
	}
}

func (mm *MixinMessenger) loopSend(ctx context.Context, period time.Duration, size int) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	var batch []*bot.MessageRequest
	filter := make(map[string]bool)
	flush := func(source string) {
		if len(batch) == 0 {
			return
		}
		err := mm.sendMessagesWithoutTimeout(ctx, batch)
		logger.Verbosef("messenger.sendMessagesWithoutTimeout(%s, %d) => %v\n", source, len(batch), err)
		filter = make(map[string]bool)
		batch = nil
	}
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-mm.send:
			if msg == nil || filter[msg.MessageId] {
				continue
			}
			filter[msg.MessageId] = true
			batch = append(batch, msg)
			if len(batch) >= size {
				flush("batch")
			}
		case <-ticker.C:
			flush("ticker")
		}
	}
}

func (mm *MixinMessenger) OnMessage(ctx context.Context, msg bot.MessageView, userID string) error {
	if msg.Category != bot.MessageCategoryEncryptedData {
		return nil
	}
	if msg.ConversationId != mm.conversationId {
		return nil
	}
	receiver, err := canonicalUUID("receiver", userID)
	if err != nil || receiver != mm.conf.UserId {
		return nil
	}
	sender, err := canonicalUUID("sender", msg.UserId)
	if err != nil || sender == receiver || !slices.Contains(mm.members, sender) {
		return nil
	}
	messageID, err := canonicalUUID("message", msg.MessageId)
	if err != nil || mm.messageSeen(messageID) {
		return nil
	}

	data, err := mm.decryptMessage(msg.DataBase64, sender, receiver, messageID)
	if err != nil {
		logger.Verbosef("messenger.OnMessage(%s, %s) rejected: %v\n", sender, messageID, err)
		return nil
	}
	received := &MixinMessage{
		Peer:      sender,
		Data:      data,
		CreatedAt: msg.CreatedAt,
	}
	select {
	case mm.recv <- received:
		mm.rememberMessage(messageID)
	case <-ctx.Done():
	}
	return nil
}

func (mm *MixinMessenger) OnAckReceipt(ctx context.Context, msg bot.MessageView, userID string) error {
	return nil
}

func (mm *MixinMessenger) SyncAck() bool {
	return true
}

func (mm *MixinMessenger) decryptMessage(data, sender, receiver, messageID string) ([]byte, error) {
	if err := validateEncryptedMessage(data, mm.conf.SessionId); err != nil {
		return nil, err
	}
	plaintext, err := bot.DecryptMessageData(data, mm.conf.SessionId, mm.privateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt messenger message: %w", err)
	}
	if plaintext == "" {
		return nil, fmt.Errorf("decrypt messenger message: authentication failed")
	}
	b, err := base64.RawURLEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decode messenger plaintext: %w", err)
	}
	return unmarshalEncryptedEnvelope(b, sender, receiver, mm.conversationId, messageID)
}

func (mm *MixinMessenger) sendMessagesWithoutTimeout(ctx context.Context, batch []*bot.MessageRequest) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := mm.postEncryptedMessages(ctx, batch)
		if err != nil && mtg.CheckRetryableError(err) {
			logger.Printf("messenger.sendMessagesWithoutTimeout(retry, %d) => %v", len(batch), err)
			if !waitForMessengerRetry(ctx, 3*time.Second) {
				return ctx.Err()
			}
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

func (mm *MixinMessenger) messageSeen(messageID string) bool {
	mm.replayMu.Lock()
	defer mm.replayMu.Unlock()
	_, found := mm.replaySeen[messageID]
	return found
}

func (mm *MixinMessenger) rememberMessage(messageID string) {
	mm.replayMu.Lock()
	defer mm.replayMu.Unlock()
	if mm.replaySeen == nil {
		mm.replaySeen = make(map[string]struct{})
	}
	if _, found := mm.replaySeen[messageID]; found {
		return
	}
	if len(mm.replayOrder) < replayCacheSize {
		mm.replayOrder = append(mm.replayOrder, messageID)
	} else {
		delete(mm.replaySeen, mm.replayOrder[mm.replayNext])
		mm.replayOrder[mm.replayNext] = messageID
		mm.replayNext = (mm.replayNext + 1) % replayCacheSize
	}
	mm.replaySeen[messageID] = struct{}{}
}

func marshalEncryptedEnvelope(sender, receiver, conversationID, messageID string, payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > maximumEncryptedMessageSize-encryptedEnvelopeHeaderSize {
		return nil, fmt.Errorf("invalid messenger payload size %d", len(payload))
	}
	ids := []string{sender, receiver, conversationID, messageID}
	b := make([]byte, 0, encryptedEnvelopeHeaderSize+len(payload))
	b = append(b, encryptedEnvelopeMagic[:]...)
	b = append(b, encryptedEnvelopeVersion)
	for _, value := range ids {
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, err
		}
		b = append(b, id.Bytes()...)
	}
	b = append(b, payload...)
	return b, nil
}

func unmarshalEncryptedEnvelope(b []byte, sender, receiver, conversationID, messageID string) ([]byte, error) {
	if len(b) <= encryptedEnvelopeHeaderSize || len(b) > maximumEncryptedMessageSize {
		return nil, fmt.Errorf("invalid messenger envelope size %d", len(b))
	}
	if !bytes.Equal(b[:len(encryptedEnvelopeMagic)], encryptedEnvelopeMagic[:]) {
		return nil, fmt.Errorf("invalid messenger envelope magic")
	}
	if b[len(encryptedEnvelopeMagic)] != encryptedEnvelopeVersion {
		return nil, fmt.Errorf("unsupported messenger envelope version %d", b[len(encryptedEnvelopeMagic)])
	}

	expected := []string{sender, receiver, conversationID, messageID}
	offset := len(encryptedEnvelopeMagic) + 1
	for i, value := range expected {
		id, err := uuid.FromBytes(b[offset : offset+16])
		if err != nil {
			return nil, fmt.Errorf("invalid messenger envelope id %d: %w", i, err)
		}
		if id.String() != value {
			return nil, fmt.Errorf("messenger envelope id %d mismatch", i)
		}
		offset += 16
	}
	payload := slices.Clone(b[offset:])
	if uniqueMessageId(receiver, payload) != messageID {
		return nil, fmt.Errorf("messenger payload id mismatch")
	}
	return payload, nil
}

func validateEncryptedMessage(data, sessionID string) error {
	maximumCiphertextSize := maximumEncryptedMessageSize + encryptedMessagePrefixSize +
		maximumRecipientSessions*encryptedMessageSessionSize + encryptedMessageNonceSize + encryptedMessageTagSize
	if len(data) > base64.RawURLEncoding.EncodedLen(maximumCiphertextSize) {
		return fmt.Errorf("encrypted messenger message is too large")
	}
	b, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("decode encrypted messenger message: %w", err)
	}
	minimumSize := encryptedMessagePrefixSize + encryptedMessageSessionSize +
		encryptedMessageNonceSize + encryptedMessageTagSize
	if len(b) < minimumSize {
		return fmt.Errorf("encrypted messenger message is too short")
	}
	if b[0] != 1 {
		return fmt.Errorf("unsupported encrypted messenger version %d", b[0])
	}
	sessionCount := int(binary.LittleEndian.Uint16(b[1:3]))
	if sessionCount == 0 || sessionCount > maximumRecipientSessions {
		return fmt.Errorf("invalid encrypted messenger session count %d", sessionCount)
	}
	prefixSize := encryptedMessagePrefixSize + sessionCount*encryptedMessageSessionSize
	if len(b) < prefixSize+encryptedMessageNonceSize+encryptedMessageTagSize {
		return fmt.Errorf("truncated encrypted messenger message")
	}

	expectedSession, err := uuid.FromString(sessionID)
	if err != nil {
		return fmt.Errorf("invalid messenger session: %w", err)
	}
	found := false
	for i := 0; i < sessionCount; i++ {
		offset := encryptedMessagePrefixSize + i*encryptedMessageSessionSize
		session, err := uuid.FromBytes(b[offset : offset+16])
		if err != nil {
			return fmt.Errorf("invalid encrypted messenger session: %w", err)
		}
		found = found || session == expectedSession
	}
	if !found {
		return fmt.Errorf("encrypted messenger message excludes this session")
	}
	return nil
}

func decodeSessionPrivateKey(key string) ([]byte, string, error) {
	seed, err := hex.DecodeString(key)
	if err != nil {
		return nil, "", fmt.Errorf("decode messenger session key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, "", fmt.Errorf("invalid messenger session key length %d", len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return seed, base64.RawURLEncoding.EncodeToString(privateKey), nil
}

func canonicalUUID(name, value string) (string, error) {
	id, err := uuid.FromString(value)
	if err != nil {
		return "", fmt.Errorf("invalid messenger %s %q: %w", name, value, err)
	}
	return id.String(), nil
}

func waitForMessengerRetry(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func uniqueMessageId(receiver string, b []byte) string {
	s := hex.EncodeToString(b)
	return common.UniqueId(receiver, s)
}
