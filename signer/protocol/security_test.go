package protocol

import (
	"bytes"
	"errors"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost"
	"github.com/stretchr/testify/require"
)

func TestProtocolMessageBindsHeadersAndRoundTrips(t *testing.T) {
	message := &Message{
		SSID:                  []byte("security-protocol-session"),
		From:                  "a",
		To:                    "b",
		Protocol:              "security/protocol",
		RoundNumber:           3,
		Data:                  []byte("payload"),
		BroadcastVerification: []byte("verification"),
	}

	raw, err := message.MarshalBinary()
	require.NoError(t, err)
	var decoded Message
	require.NoError(t, decoded.UnmarshalBinary(raw))
	require.Equal(t, message, &decoded)
	require.Equal(t, message.Hash(), decoded.Hash())

	baseline := message.Hash()
	mutations := []struct {
		name  string
		apply func(*Message)
	}{
		{name: "ssid", apply: func(m *Message) { m.SSID = []byte("other-session") }},
		{name: "sender", apply: func(m *Message) { m.From = "c" }},
		{name: "receiver", apply: func(m *Message) { m.To = "c" }},
		{name: "protocol", apply: func(m *Message) { m.Protocol = "other/protocol" }},
		{name: "round", apply: func(m *Message) { m.RoundNumber++ }},
		{name: "payload", apply: func(m *Message) { m.Data = []byte("other-payload") }},
		{name: "broadcast", apply: func(m *Message) { m.Broadcast = true }},
		{name: "broadcast verification", apply: func(m *Message) {
			m.BroadcastVerification = []byte("other-verification")
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := securityTestCloneProtocolMessage(message)
			mutation.apply(candidate)
			require.NotEqual(t, baseline, candidate.Hash())
		})
	}

	require.False(t, message.IsFor("a"))
	require.True(t, message.IsFor("b"))
	require.False(t, message.IsFor("c"))
	require.Error(t, decoded.UnmarshalBinary([]byte{0xff}))
}

func TestMultiHandlerRejectsSessionAndRoutingSubstitution(t *testing.T) {
	a, b := securityTestProtocolHandlers(t)
	message := securityTestFirstProtocolMessage(t, a, true)
	require.True(t, b.CanAccept(message))

	mutations := []struct {
		name  string
		apply func(*Message)
	}{
		{name: "broadcast with destination", apply: func(m *Message) { m.To = "b" }},
		{name: "wrong session", apply: func(m *Message) { m.SSID = []byte("wrong-session") }},
		{name: "wrong protocol", apply: func(m *Message) { m.Protocol = "wrong/protocol" }},
		{name: "unknown sender", apply: func(m *Message) { m.From = "attacker" }},
		{name: "self sender", apply: func(m *Message) { m.From = "b" }},
		{name: "nil payload", apply: func(m *Message) { m.Data = nil }},
		{name: "round beyond protocol", apply: func(m *Message) { m.RoundNumber = 0xffff }},
		{name: "unicast without destination", apply: func(m *Message) { m.Broadcast = false }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := securityTestCloneProtocolMessage(message)
			mutation.apply(candidate)
			require.False(t, b.CanAccept(candidate))
		})
	}
}

func TestMultiHandlerRejectsCorruptAndDuplicateMessages(t *testing.T) {
	t.Run("corrupt payload aborts", func(t *testing.T) {
		a, b := securityTestProtocolHandlers(t)
		message := securityTestFirstProtocolMessage(t, a, true)
		message.Data = []byte{0xff, 0x00, 0x01}
		require.True(t, b.CanAccept(message))
		require.False(t, b.Accept(message))
		_, err := b.Result()
		require.ErrorContains(t, err, "failed to unmarshal")
		var protocolError Error
		require.ErrorAs(t, err, &protocolError)
		require.Equal(t, []party.ID{"a"}, protocolError.Culprits)
	})

	t.Run("duplicate is ignored", func(t *testing.T) {
		a, b := securityTestProtocolHandlers(t)
		message := securityTestFirstProtocolMessage(t, a, true)
		require.True(t, b.Accept(message))
		require.False(t, b.Accept(message))
	})
}

func TestMultiHandlerHandlesNormalAndBroadcastOrdering(t *testing.T) {
	advance := func(t *testing.T) (*MultiHandler, *MultiHandler) {
		t.Helper()
		a, b := securityTestProtocolHandlers(t)
		fromA := securityTestDrainProtocolMessages(a)
		fromB := securityTestDrainProtocolMessages(b)
		for _, message := range fromA {
			require.True(t, b.Accept(message))
		}
		for _, message := range fromB {
			require.True(t, a.Accept(message))
		}
		return a, b
	}
	findMessages := func(t *testing.T, handler *MultiHandler) (broadcast, normal *Message) {
		t.Helper()
		for _, message := range securityTestDrainProtocolMessages(handler) {
			if message.Broadcast {
				broadcast = securityTestCloneProtocolMessage(message)
			} else {
				normal = securityTestCloneProtocolMessage(message)
			}
		}
		require.NotNil(t, broadcast)
		require.NotNil(t, normal)
		return broadcast, normal
	}

	t.Run("normal message may arrive before broadcast", func(t *testing.T) {
		a, b := advance(t)
		broadcast, normal := findMessages(t, a)
		require.True(t, b.Accept(normal))
		require.True(t, b.Accept(broadcast))
	})

	t.Run("corrupt normal message aborts after broadcast", func(t *testing.T) {
		a, b := advance(t)
		broadcast, normal := findMessages(t, a)
		require.True(t, b.Accept(broadcast))
		normal.Data = []byte{0xff}
		require.False(t, b.Accept(normal))
		_, err := b.Result()
		require.ErrorContains(t, err, "failed to unmarshal")
	})
}

func TestMultiHandlerForwardedAbortDoesNotFrameSender(t *testing.T) {
	_, b := securityTestProtocolHandlers(t)
	abort := &Message{
		SSID:        bytes.Clone(b.currentRound.SSID()),
		From:        "a",
		To:          "b",
		Protocol:    b.currentRound.ProtocolID(),
		RoundNumber: 0,
		Data:        []byte("abort requested"),
	}
	require.True(t, b.CanAccept(abort))
	require.False(t, b.Accept(abort))
	_, err := b.Result()
	require.Error(t, err)
	var protocolError Error
	require.ErrorAs(t, err, &protocolError)
	require.Empty(t, protocolError.Culprits)
	require.ErrorContains(t, err, "aborted by other party")

	inner := errors.New("inner")
	require.ErrorIs(t, Error{Err: inner}, inner)
}

func TestMultiHandlerStopAndDiagnosticSurfaces(t *testing.T) {
	a, _ := securityTestProtocolHandlers(t)
	require.Contains(t, a.String(), "party: a")
	require.Contains(t, a.String(), a.currentRound.ProtocolID())
	require.Contains(t, (&Message{
		RoundNumber: 2,
		From:        "a",
		To:          "b",
		Protocol:    "test/protocol",
	}).String(), "round 2")

	result, err := a.Result()
	require.Nil(t, result)
	require.ErrorContains(t, err, "not finished")
	require.False(t, a.CanAccept(nil))

	a.Stop()
	a.Stop()
	result, err = a.Result()
	require.Nil(t, result)
	require.ErrorContains(t, err, "aborted by user")
	var protocolError Error
	require.ErrorAs(t, err, &protocolError)
	require.Equal(t, []party.ID{"a"}, protocolError.Culprits)
}

func TestMultiHandlerRejectsMismatchedBroadcastVerification(t *testing.T) {
	a, b := securityTestProtocolHandlers(t)
	number := b.currentRound.Number()
	require.NoError(t, b.verifyMessage(&Message{
		RoundNumber: number,
		From:        "a",
		To:          "b",
		Data:        []byte{0},
	}))
	b.broadcastHashes[number-1] = []byte("expected")
	b.messages[number]["a"] = &Message{BroadcastVerification: []byte("substituted")}
	require.False(t, b.checkBroadcastHash())
	b.messages[number]["a"].BroadcastVerification = []byte("expected")
	b.broadcast[number]["a"] = &Message{BroadcastVerification: []byte("substituted")}
	require.False(t, b.checkBroadcastHash())

	for _, queue := range []map[party.ID]*Message{b.messages[number], b.broadcast[number]} {
		for _, message := range queue {
			if message != nil {
				message.BroadcastVerification = []byte("expected")
			}
		}
	}
	require.True(t, b.checkBroadcastHash())

	unknown := &Message{RoundNumber: b.currentRound.FinalRoundNumber() + 1, From: "a"}
	require.NoError(t, b.verifyBroadcastMessage(unknown))
	require.NoError(t, b.verifyMessage(unknown))
	require.True(t, b.duplicate(unknown))
	b.store(unknown)

	first := b.rounds[1]
	require.NotNil(t, first)
	_, err := getRoundMessage(&Message{Broadcast: true}, first)
	require.ErrorContains(t, err, "broadcast message")

	future := securityTestFirstProtocolMessage(t, a, true)
	future.RoundNumber = b.currentRound.Number() + 1
	require.True(t, b.CanAccept(future))
	require.False(t, b.Accept(future))
	require.True(t, b.duplicate(future))
}

func TestMultiHandlerCompletesFROSTExchange(t *testing.T) {
	ids := []party.ID{"a", "b"}
	handlers := make(map[party.ID]*MultiHandler, len(ids))
	for _, id := range ids {
		start, err := frost.Keygen(curve.Secp256k1{}, id, ids, 1)([]byte("full-security-exchange"))
		require.NoError(t, err)
		handlers[id], err = NewMultiHandler(start)
		require.NoError(t, err)
	}

	for range 20 {
		var outgoing []*Message
		for _, handler := range handlers {
			outgoing = append(outgoing, securityTestDrainProtocolMessages(handler)...)
		}
		if len(outgoing) == 0 {
			break
		}
		for _, message := range outgoing {
			for _, handler := range handlers {
				if handler.CanAccept(message) {
					handler.Accept(message)
				}
			}
		}
	}

	for id, handler := range handlers {
		result, err := handler.Result()
		require.NoError(t, err, id)
		require.NotNil(t, result, id)
	}
}

func FuzzProtocolMessageBinary(f *testing.F) {
	seed := &Message{
		SSID:                  []byte("fuzz-session"),
		From:                  "a",
		To:                    "b",
		Protocol:              "fuzz/protocol",
		RoundNumber:           2,
		Data:                  []byte("payload"),
		BroadcastVerification: []byte("verification"),
	}
	raw, err := seed.MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var message Message
		if err := message.UnmarshalBinary(data); err != nil {
			return
		}
		_ = message.Hash()
		_ = message.IsFor("fuzz-recipient")
		encoded, err := message.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var decoded Message
		if err := decoded.UnmarshalBinary(encoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(message.Hash(), decoded.Hash()) {
			t.Fatal("message hash changed after canonical round trip")
		}
	})
}

func FuzzProtocolRoundPayload(f *testing.F) {
	a, b := securityTestProtocolHandlersFuzz(f)
	message := securityTestFirstProtocolMessageFuzz(f, a, true)
	f.Add(bytes.Clone(message.Data))
	f.Add([]byte{0xff, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		candidate := securityTestCloneProtocolMessage(message)
		candidate.Data = bytes.Clone(data)
		_, _ = getRoundMessage(candidate, b.currentRound)
	})
}

func securityTestProtocolHandlers(t *testing.T) (*MultiHandler, *MultiHandler) {
	t.Helper()
	ids := []party.ID{"a", "b"}
	startA, err := frost.Keygen(curve.Secp256k1{}, "a", ids, 1)([]byte("security-handler-session"))
	require.NoError(t, err)
	startB, err := frost.Keygen(curve.Secp256k1{}, "b", ids, 1)([]byte("security-handler-session"))
	require.NoError(t, err)
	a, err := NewMultiHandler(startA)
	require.NoError(t, err)
	b, err := NewMultiHandler(startB)
	require.NoError(t, err)
	return a, b
}

func securityTestProtocolHandlersFuzz(f *testing.F) (*MultiHandler, *MultiHandler) {
	f.Helper()
	ids := []party.ID{"a", "b"}
	startA, err := frost.Keygen(curve.Secp256k1{}, "a", ids, 1)([]byte("security-fuzz-session"))
	if err != nil {
		f.Fatal(err)
	}
	startB, err := frost.Keygen(curve.Secp256k1{}, "b", ids, 1)([]byte("security-fuzz-session"))
	if err != nil {
		f.Fatal(err)
	}
	a, err := NewMultiHandler(startA)
	if err != nil {
		f.Fatal(err)
	}
	b, err := NewMultiHandler(startB)
	if err != nil {
		f.Fatal(err)
	}
	return a, b
}

func securityTestFirstProtocolMessage(t *testing.T, handler *MultiHandler, broadcast bool) *Message {
	t.Helper()
	for _, message := range securityTestDrainProtocolMessages(handler) {
		if message.Broadcast == broadcast {
			return securityTestCloneProtocolMessage(message)
		}
	}
	t.Fatalf("no broadcast=%t protocol message", broadcast)
	return nil
}

func securityTestFirstProtocolMessageFuzz(f *testing.F, handler *MultiHandler, broadcast bool) *Message {
	f.Helper()
	for _, message := range securityTestDrainProtocolMessages(handler) {
		if message.Broadcast == broadcast {
			return securityTestCloneProtocolMessage(message)
		}
	}
	f.Fatalf("no broadcast=%t protocol message", broadcast)
	return nil
}

func securityTestDrainProtocolMessages(handler *MultiHandler) []*Message {
	var messages []*Message
	for {
		select {
		case message, open := <-handler.Listen():
			if !open {
				return messages
			}
			messages = append(messages, message)
		default:
			return messages
		}
	}
}

func securityTestCloneProtocolMessage(message *Message) *Message {
	clone := *message
	clone.SSID = bytes.Clone(message.SSID)
	clone.Data = bytes.Clone(message.Data)
	clone.BroadcastVerification = bytes.Clone(message.BroadcastVerification)
	return &clone
}
