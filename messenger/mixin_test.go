package messenger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
)

const (
	testSenderID          = "11111111-1111-4111-8111-111111111111"
	testReceiverID        = "22222222-2222-4222-8222-222222222222"
	testThirdMemberID     = "33333333-3333-4333-8333-333333333333"
	testSenderSessionID   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testReceiverSessionID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	testConversationID    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func TestMixinMessengerEncryptedMessageRoundTrip(t *testing.T) {
	sender, receiver, view := makeEncryptedTestMessage(t, []byte("frost secret share"))
	if view.Category != bot.MessageCategoryEncryptedData {
		t.Fatalf("category %q, want %q", view.Category, bot.MessageCategoryEncryptedData)
	}

	if err := receiver.OnMessage(t.Context(), view, testReceiverID); err != nil {
		t.Fatal(err)
	}
	message, err := receiver.ReceiveMessage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if message.Peer != testSenderID {
		t.Fatalf("peer %q, want %q", message.Peer, testSenderID)
	}
	if !bytes.Equal(message.Data, []byte("frost secret share")) {
		t.Fatalf("data %q", message.Data)
	}
	if !message.CreatedAt.Equal(view.CreatedAt) {
		t.Fatalf("created at %s, want %s", message.CreatedAt, view.CreatedAt)
	}

	request, err := sender.buildMessage(testReceiverID, message.Data)
	if err != nil {
		t.Fatal(err)
	}
	if request.DataBase64 == view.DataBase64 {
		t.Fatal("wire message contains the unencrypted envelope")
	}
}

func TestMixinMessengerRejectsTamperingAndMetadataSubstitution(t *testing.T) {
	t.Run("ciphertext", func(t *testing.T) {
		_, receiver, view := makeEncryptedTestMessage(t, []byte("round two share"))
		ciphertext, err := base64.RawURLEncoding.DecodeString(view.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext[len(ciphertext)-1] ^= 1
		view.DataBase64 = base64.RawURLEncoding.EncodeToString(ciphertext)

		if err := receiver.OnMessage(t.Context(), view, testReceiverID); err != nil {
			t.Fatal(err)
		}
		if len(receiver.recv) != 0 {
			t.Fatal("tampered ciphertext was delivered")
		}
	})

	t.Run("message id", func(t *testing.T) {
		_, receiver, view := makeEncryptedTestMessage(t, []byte("round three share"))
		view.MessageId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

		if err := receiver.OnMessage(t.Context(), view, testReceiverID); err != nil {
			t.Fatal(err)
		}
		if len(receiver.recv) != 0 {
			t.Fatal("message with substituted metadata was delivered")
		}
	})

	t.Run("sender", func(t *testing.T) {
		_, receiver, view := makeEncryptedTestMessage(t, []byte("round four share"))
		view.UserId = testThirdMemberID

		if err := receiver.OnMessage(t.Context(), view, testReceiverID); err != nil {
			t.Fatal(err)
		}
		if len(receiver.recv) != 0 {
			t.Fatal("message with substituted sender was delivered")
		}
	})
}

func TestMixinMessengerRejectsPlaintextAndMalformedEncryption(t *testing.T) {
	receiver := newTestMixinMessenger(t, testReceiverID, testReceiverSessionID, 2)
	messageID := uniqueMessageId(testReceiverID, []byte("plaintext"))
	plain := bot.MessageView{
		ConversationId: testConversationID,
		UserId:         testSenderID,
		MessageId:      messageID,
		Category:       bot.MessageCategoryPlainData,
		DataBase64:     base64.RawURLEncoding.EncodeToString([]byte("plaintext")),
	}
	if err := receiver.OnMessage(t.Context(), plain, testReceiverID); err != nil {
		t.Fatal(err)
	}

	malformed := make([]byte, encryptedMessagePrefixSize+encryptedMessageSessionSize+
		encryptedMessageNonceSize+encryptedMessageTagSize)
	malformed[0] = 1
	binary.LittleEndian.PutUint16(malformed[1:3], maximumRecipientSessions+1)
	encrypted := plain
	encrypted.Category = bot.MessageCategoryEncryptedData
	encrypted.DataBase64 = base64.RawURLEncoding.EncodeToString(malformed)
	if err := receiver.OnMessage(t.Context(), encrypted, testReceiverID); err != nil {
		t.Fatal(err)
	}
	if len(receiver.recv) != 0 {
		t.Fatal("plaintext or malformed encrypted message was delivered")
	}
}

func TestMixinMessengerDropsReplayedMessage(t *testing.T) {
	_, receiver, view := makeEncryptedTestMessage(t, []byte("replay protected"))
	if err := receiver.OnMessage(t.Context(), view, testReceiverID); err != nil {
		t.Fatal(err)
	}
	if err := receiver.OnMessage(t.Context(), view, testReceiverID); err != nil {
		t.Fatal(err)
	}
	if len(receiver.recv) != 1 {
		t.Fatalf("received %d copies, want 1", len(receiver.recv))
	}
}

func TestMixinMessengerBroadcastEncryptsForEveryPeer(t *testing.T) {
	sender := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	var sent []*bot.MessageRequest
	sender.postEncryptedMessages = func(_ context.Context, messages []*bot.MessageRequest) error {
		sent = slices.Clone(messages)
		return nil
	}

	payload := []byte("broadcast round")
	if err := sender.BroadcastMessage(t.Context(), payload); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 {
		t.Fatalf("sent %d messages, want 2", len(sent))
	}
	recipients := []string{sent[0].RecipientId, sent[1].RecipientId}
	slices.Sort(recipients)
	want := []string{testReceiverID, testThirdMemberID}
	if !slices.Equal(recipients, want) {
		t.Fatalf("recipients %v, want %v", recipients, want)
	}
	for _, message := range sent {
		if message.Category != bot.MessageCategoryEncryptedData {
			t.Fatalf("category %q, want encrypted data", message.Category)
		}
		envelope, err := base64.RawURLEncoding.DecodeString(message.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unmarshalEncryptedEnvelope(
			envelope,
			testSenderID,
			message.RecipientId,
			testConversationID,
			message.MessageId,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload %q", got)
		}
	}
}

func TestValidateEncryptedMessageRejectsTruncatedSessionTable(t *testing.T) {
	message := make([]byte, encryptedMessagePrefixSize+encryptedMessageSessionSize+
		encryptedMessageNonceSize+encryptedMessageTagSize)
	message[0] = 1
	binary.LittleEndian.PutUint16(message[1:3], 2)
	err := validateEncryptedMessage(
		base64.RawURLEncoding.EncodeToString(message),
		testReceiverSessionID,
	)
	if err == nil {
		t.Fatal("truncated session table accepted")
	}
}

func makeEncryptedTestMessage(t *testing.T, payload []byte) (*MixinMessenger, *MixinMessenger, bot.MessageView) {
	t.Helper()
	sender := newTestMixinMessenger(t, testSenderID, testSenderSessionID, 1)
	receiver := newTestMixinMessenger(t, testReceiverID, testReceiverSessionID, 2)
	request, err := sender.buildMessage(testReceiverID, payload)
	if err != nil {
		t.Fatal(err)
	}

	receiverPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	receiverPublic, err := bot.PublicKeyToCurve25519(receiverPrivate.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sessions := []*bot.Session{{
		UserID:    testReceiverID,
		SessionID: testReceiverSessionID,
		PublicKey: base64.RawURLEncoding.EncodeToString(receiverPublic),
	}}
	ciphertext, err := bot.EncryptMessageData(request.DataBase64, sessions, sender.user.SessionPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver, bot.MessageView{
		ConversationId: request.ConversationId,
		UserId:         testSenderID,
		MessageId:      request.MessageId,
		Category:       request.Category,
		DataBase64:     ciphertext,
		CreatedAt:      time.Unix(1_700_000_000, 123).UTC(),
	}
}

func newTestMixinMessenger(t *testing.T, userID, sessionID string, seed byte) *MixinMessenger {
	t.Helper()
	key := hex.EncodeToString(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return &MixinMessenger{
		members:        []string{testSenderID, testReceiverID, testThirdMemberID},
		conf:           &MixinConfiguration{UserId: userID, SessionId: sessionID},
		conversationId: testConversationID,
		user:           bot.NewSafeUser(userID, sessionID, key),
		recv:           make(chan *MixinMessage, 8),
		replaySeen:     make(map[string]struct{}),
	}
}
