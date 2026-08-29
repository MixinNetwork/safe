package messenger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	bot "github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func TestNewMixinMessengerConfigurationValidation(t *testing.T) {
	_, err := NewMixinMessenger(t.Context(), nil, nil)
	require.ErrorContains(t, err, "configuration is nil")

	tests := []struct {
		name    string
		mutate  func(*MixinConfiguration, *[]string)
		message string
	}{
		{name: "zero send buffer", mutate: func(c *MixinConfiguration, _ *[]string) { c.SendBuffer = 0 }, message: "messages limit"},
		{name: "maximum send buffer", mutate: func(c *MixinConfiguration, _ *[]string) { c.SendBuffer = maximumSendBuffer }, message: "messages limit"},
		{name: "zero receive buffer", mutate: func(c *MixinConfiguration, _ *[]string) { c.ReceiveBuffer = 0 }, message: "receive buffer"},
		{name: "invalid user", mutate: func(c *MixinConfiguration, _ *[]string) { c.UserId = "invalid" }, message: "invalid messenger user"},
		{name: "invalid session", mutate: func(c *MixinConfiguration, _ *[]string) { c.SessionId = "invalid" }, message: "invalid messenger session"},
		{name: "invalid conversation", mutate: func(c *MixinConfiguration, _ *[]string) { c.ConversationId = "invalid" }, message: "invalid messenger conversation"},
		{name: "invalid member", mutate: func(_ *MixinConfiguration, members *[]string) { (*members)[0] = "invalid" }, message: "invalid messenger member"},
		{name: "duplicate member", mutate: func(_ *MixinConfiguration, members *[]string) { *members = append(*members, (*members)[0]) }, message: "duplicate messenger member"},
		{name: "user absent", mutate: func(_ *MixinConfiguration, members *[]string) { *members = []string{testReceiverID} }, message: "is not a member"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := coverageMixinConfiguration()
			members := []string{testThirdMemberID, testSenderID, testReceiverID}
			test.mutate(configuration, &members)
			_, err := NewMixinMessenger(t.Context(), configuration, members)
			require.ErrorContains(t, err, test.message)
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	messenger, err := NewMixinMessenger(ctx, coverageMixinConfiguration(), []string{
		testThirdMemberID, testSenderID, testReceiverID,
	})
	require.NoError(t, err)
	require.Equal(t, []string{testSenderID, testReceiverID, testThirdMemberID}, messenger.members)
	require.Equal(t, testSenderID, messenger.conf.UserId)
}

func TestMixinMessengerSendQueueAndReceiveBoundaries(t *testing.T) {
	messenger := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	messenger.send = make(chan *bot.MessageRequest, 1)
	var sent []*bot.MessageRequest
	messenger.postEncryptedMessages = func(_ context.Context, messages []*bot.MessageRequest) error {
		sent = slices.Clone(messages)
		return nil
	}

	require.NoError(t, messenger.SendMessage(t.Context(), testReceiverID, []byte("direct")))
	require.Len(t, sent, 1)
	require.Equal(t, testReceiverID, sent[0].RecipientId)

	require.NoError(t, messenger.QueueMessage(t.Context(), testReceiverID, []byte("queued")))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, messenger.QueueMessage(ctx, testReceiverID, []byte("blocked")), ErrorDone)

	require.Error(t, messenger.SendMessage(t.Context(), "invalid", []byte("payload")))
	require.Error(t, messenger.SendMessage(t.Context(), testSenderID, []byte("payload")))
	require.Error(t, messenger.SendMessage(t.Context(), "44444444-4444-4444-8444-444444444444", []byte("payload")))
	require.Error(t, messenger.SendMessage(t.Context(), testReceiverID, nil))
	require.Error(t, messenger.SendMessage(t.Context(), testReceiverID,
		make([]byte, maximumEncryptedMessageSize-encryptedEnvelopeHeaderSize+1)))

	messenger.recv <- nil
	message, err := messenger.ReceiveMessage(t.Context())
	require.Nil(t, message)
	require.ErrorIs(t, err, ErrorDone)

	empty := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	message, err = empty.ReceiveMessage(canceled)
	require.Nil(t, message)
	require.ErrorIs(t, err, ErrorDone)
}

func TestMixinMessengerLoopSendBatchesDeduplicatesAndFlushes(t *testing.T) {
	messenger := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	messenger.send = make(chan *bot.MessageRequest, 8)
	batches := make(chan []*bot.MessageRequest, 2)
	messenger.postEncryptedMessages = func(_ context.Context, messages []*bot.MessageRequest) error {
		batches <- slices.Clone(messages)
		return nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		messenger.loopSend(ctx, time.Hour, 2)
		close(done)
	}()
	messenger.send <- nil
	messenger.send <- &bot.MessageRequest{MessageId: "one"}
	messenger.send <- &bot.MessageRequest{MessageId: "one"}
	messenger.send <- &bot.MessageRequest{MessageId: "two"}
	select {
	case batch := <-batches:
		require.Equal(t, []string{"one", "two"}, []string{batch[0].MessageId, batch[1].MessageId})
	case <-time.After(time.Second):
		t.Fatal("batch was not flushed")
	}
	cancel()
	<-done

	messenger.send = make(chan *bot.MessageRequest, 1)
	ctx, cancel = context.WithCancel(t.Context())
	done = make(chan struct{})
	go func() {
		messenger.loopSend(ctx, time.Millisecond, 2)
		close(done)
	}()
	messenger.send <- &bot.MessageRequest{MessageId: "ticker"}
	select {
	case batch := <-batches:
		require.Equal(t, "ticker", batch[0].MessageId)
	case <-time.After(time.Second):
		t.Fatal("ticker batch was not flushed")
	}
	cancel()
	<-done
}

func TestMixinMessengerMetadataFiltersAndCallbacks(t *testing.T) {
	_, _, valid := makeEncryptedTestMessage(t, []byte("metadata"))
	tests := []struct {
		name   string
		userID string
		mutate func(*bot.MessageView)
	}{
		{name: "category", userID: testReceiverID, mutate: func(v *bot.MessageView) { v.Category = bot.MessageCategoryPlainData }},
		{name: "conversation", userID: testReceiverID, mutate: func(v *bot.MessageView) { v.ConversationId = testThirdMemberID }},
		{name: "invalid receiver", userID: "invalid", mutate: func(*bot.MessageView) {}},
		{name: "other receiver", userID: testThirdMemberID, mutate: func(*bot.MessageView) {}},
		{name: "invalid sender", userID: testReceiverID, mutate: func(v *bot.MessageView) { v.UserId = "invalid" }},
		{name: "self sender", userID: testReceiverID, mutate: func(v *bot.MessageView) { v.UserId = testReceiverID }},
		{name: "unknown sender", userID: testReceiverID, mutate: func(v *bot.MessageView) { v.UserId = "44444444-4444-4444-8444-444444444444" }},
		{name: "invalid message", userID: testReceiverID, mutate: func(v *bot.MessageView) { v.MessageId = "invalid" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receiver := newTestMixinMessenger(t, testReceiverID, testReceiverSessionID, 2)
			view := valid
			test.mutate(&view)
			require.NoError(t, receiver.OnMessage(t.Context(), view, test.userID))
			require.Empty(t, receiver.recv)
		})
	}

	messenger := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	require.NoError(t, messenger.OnAckReceipt(t.Context(), bot.MessageView{}, testReceiverID))
	require.True(t, messenger.SyncAck())
}

func TestMixinMessengerPostRetryAndLargeBatchSplitting(t *testing.T) {
	batch := []*bot.MessageRequest{
		{MessageId: "one"}, {MessageId: "two"}, {MessageId: "three"}, {MessageId: "four"},
	}

	messenger := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	messenger.postEncryptedMessages = func(context.Context, []*bot.MessageRequest) error {
		return errors.New("fatal")
	}
	require.ErrorContains(t, messenger.sendMessagesWithoutTimeout(t.Context(), batch), "fatal")

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, messenger.sendMessagesWithoutTimeout(canceled, batch), context.Canceled)

	retryContext, cancelRetry := context.WithCancel(t.Context())
	messenger.postEncryptedMessages = func(context.Context, []*bot.MessageRequest) error {
		cancelRetry()
		return errors.New("EOF")
	}
	require.ErrorIs(t, messenger.sendMessagesWithoutTimeout(retryContext, batch), context.Canceled)

	var sizes []int
	messenger.postEncryptedMessages = func(_ context.Context, messages []*bot.MessageRequest) error {
		sizes = append(sizes, len(messages))
		if len(messages) > 1 {
			return errors.New("413 Request Entity Too Large")
		}
		return nil
	}
	require.NoError(t, messenger.sendMessagesWithoutTimeout(t.Context(), batch))
	require.Equal(t, []int{4, 2, 1, 1, 2, 1, 1}, sizes)

	messenger.postEncryptedMessages = func(context.Context, []*bot.MessageRequest) error {
		return errors.New("413 Request Entity Too Large")
	}
	require.ErrorContains(t, messenger.sendMessagesWithoutTimeout(t.Context(), batch[:1]), "413")
}

func TestMixinMessengerReplayCacheEviction(t *testing.T) {
	messenger := &MixinMessenger{}
	messenger.rememberMessage("first")
	messenger.rememberMessage("first")
	require.True(t, messenger.messageSeen("first"))
	for i := 1; i <= replayCacheSize; i++ {
		messenger.rememberMessage(fmt.Sprintf("message-%d", i))
	}
	require.False(t, messenger.messageSeen("first"))
	require.True(t, messenger.messageSeen(fmt.Sprintf("message-%d", replayCacheSize)))
}

func TestEncryptedEnvelopeValidationBranches(t *testing.T) {
	payload := []byte("envelope payload")
	messageID := uniqueMessageId(testReceiverID, payload)
	envelope, err := marshalEncryptedEnvelope(
		testSenderID, testReceiverID, testConversationID, messageID, payload,
	)
	require.NoError(t, err)
	decoded, err := unmarshalEncryptedEnvelope(
		envelope, testSenderID, testReceiverID, testConversationID, messageID,
	)
	require.NoError(t, err)
	require.Equal(t, payload, decoded)

	_, err = marshalEncryptedEnvelope(testSenderID, testReceiverID, testConversationID, messageID, nil)
	require.Error(t, err)
	_, err = marshalEncryptedEnvelope(testSenderID, testReceiverID, testConversationID, messageID,
		make([]byte, maximumEncryptedMessageSize-encryptedEnvelopeHeaderSize+1))
	require.Error(t, err)
	_, err = marshalEncryptedEnvelope("invalid", testReceiverID, testConversationID, messageID, payload)
	require.Error(t, err)

	_, err = unmarshalEncryptedEnvelope(envelope[:encryptedEnvelopeHeaderSize], testSenderID, testReceiverID, testConversationID, messageID)
	require.ErrorContains(t, err, "size")
	_, err = unmarshalEncryptedEnvelope(make([]byte, maximumEncryptedMessageSize+1), testSenderID, testReceiverID, testConversationID, messageID)
	require.ErrorContains(t, err, "size")

	mutated := bytes.Clone(envelope)
	mutated[0] ^= 1
	_, err = unmarshalEncryptedEnvelope(mutated, testSenderID, testReceiverID, testConversationID, messageID)
	require.ErrorContains(t, err, "magic")
	mutated = bytes.Clone(envelope)
	mutated[len(encryptedEnvelopeMagic)]++
	_, err = unmarshalEncryptedEnvelope(mutated, testSenderID, testReceiverID, testConversationID, messageID)
	require.ErrorContains(t, err, "version")

	wrong := "44444444-4444-4444-8444-444444444444"
	for index, values := range [][4]string{
		{wrong, testReceiverID, testConversationID, messageID},
		{testSenderID, wrong, testConversationID, messageID},
		{testSenderID, testReceiverID, wrong, messageID},
		{testSenderID, testReceiverID, testConversationID, wrong},
	} {
		_, err = unmarshalEncryptedEnvelope(envelope, values[0], values[1], values[2], values[3])
		require.ErrorContains(t, err, fmt.Sprintf("id %d mismatch", index))
	}
	mutated = bytes.Clone(envelope)
	mutated[len(mutated)-1] ^= 1
	_, err = unmarshalEncryptedEnvelope(mutated, testSenderID, testReceiverID, testConversationID, messageID)
	require.ErrorContains(t, err, "payload id")
}

func TestEncryptedMessageStructuralValidationBranches(t *testing.T) {
	maximumCiphertextSize := maximumEncryptedMessageSize + encryptedMessagePrefixSize +
		maximumRecipientSessions*encryptedMessageSessionSize + encryptedMessageNonceSize + encryptedMessageTagSize
	require.ErrorContains(t, validateEncryptedMessage(
		strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maximumCiphertextSize)+1), testReceiverSessionID,
	), "too large")
	require.ErrorContains(t, validateEncryptedMessage("%", testReceiverSessionID), "decode")
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString([]byte{1}), testReceiverSessionID), "too short")

	valid := coverageEncryptedMessage(testReceiverSessionID, 1)
	require.NoError(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(valid), testReceiverSessionID))

	mutated := bytes.Clone(valid)
	mutated[0] = 2
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(mutated), testReceiverSessionID), "version")
	mutated = bytes.Clone(valid)
	binary.LittleEndian.PutUint16(mutated[1:3], 0)
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(mutated), testReceiverSessionID), "session count")
	mutated = bytes.Clone(valid)
	binary.LittleEndian.PutUint16(mutated[1:3], maximumRecipientSessions+1)
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(mutated), testReceiverSessionID), "session count")
	mutated = bytes.Clone(valid)
	binary.LittleEndian.PutUint16(mutated[1:3], 2)
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(mutated), testReceiverSessionID), "truncated")
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(valid), "invalid"), "invalid messenger session")

	excluded := coverageEncryptedMessage(testSenderSessionID, 1)
	require.ErrorContains(t, validateEncryptedMessage(base64.RawURLEncoding.EncodeToString(excluded), testReceiverSessionID), "excludes")

	canonical, err := canonicalUUID("test", strings.ToUpper(testReceiverID))
	require.NoError(t, err)
	require.Equal(t, testReceiverID, canonical)
	_, err = canonicalUUID("test", "invalid")
	require.Error(t, err)
}

func TestWaitForMessengerRetry(t *testing.T) {
	require.True(t, waitForMessengerRetry(t.Context(), time.Millisecond))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, waitForMessengerRetry(ctx, time.Hour))
}

func coverageMixinConfiguration() *MixinConfiguration {
	return &MixinConfiguration{
		UserId:         testSenderID,
		SessionId:      testSenderSessionID,
		Key:            hex.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SeedSize)),
		SendBuffer:     4,
		ReceiveBuffer:  4,
		ConversationId: testConversationID,
	}
}

func coverageEncryptedMessage(sessionID string, count int) []byte {
	b := make([]byte, encryptedMessagePrefixSize+count*encryptedMessageSessionSize+
		encryptedMessageNonceSize+encryptedMessageTagSize)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[1:3], uint16(count))
	id := uuid.Must(uuid.FromString(sessionID))
	copy(b[encryptedMessagePrefixSize:encryptedMessagePrefixSize+16], id.Bytes())
	return b
}
