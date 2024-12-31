package computer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"runtime"
	"slices"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/protocol"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) bootSigner(ctx context.Context) {
	go node.loopBackup(ctx)
	go node.loopInitialSessions(ctx)
	go node.loopPreparedSessions(ctx)
	go node.loopPendingSessions(ctx)
	go node.acceptIncomingMessages(ctx)
}

func (node *Node) loopBackup(ctx context.Context) {
	for {
		time.Sleep(5 * time.Second)
		keys, err := node.store.ListUnbackupedKeys(ctx, 1000)
		if err != nil {
			panic(err)
		}

		for _, key := range keys {
			share, err := common.Base91Decode(key.Share)
			if err != nil {
				panic(err)
			}
			op := keyAsOperation(key)
			saved, err := node.sendKeygenBackup(ctx, op, share)
			logger.Printf("node.sendKeygenBackup(%v, %d) => %t %v", op, len(share), saved, err)
			if err != nil {
				panic(err)
			}
			if !saved {
				continue
			}
			err = node.store.MarkKeyBackuped(ctx, op.Public)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) loopInitialSessions(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		synced := node.synced(ctx)
		if !synced {
			logger.Printf("group.Synced(%s) => %t", node.group.GenesisId(), synced)
			continue
		}
		sessions, err := node.store.ListInitialSessions(ctx, 64)
		if err != nil {
			panic(err)
		}

		for _, s := range sessions {
			traceId := fmt.Sprintf("SESSION:%s:SIGNER:%s:PREPARE", s.Id, string(node.id))
			extra := []byte{OperationTypeSignInput}
			extra = append(extra, uuid.Must(uuid.FromString(s.Id)).Bytes()...)
			extra = append(extra, PrepareExtra...)
			err := node.sendTransactionToGroupUntilSufficient(ctx, extra, traceId)
			logger.Printf("node.sendTransactionToGroupUntilSufficient(%x %s) => %v", extra, traceId, err)
			if err != nil {
				break
			}
			err = node.store.MarkSessionCommitted(ctx, s.Id)
			logger.Printf("node.MarkSessionCommitted(%v) => %v", s, err)
			if err != nil {
				break
			}
		}
	}
}

func (node *Node) loopPreparedSessions(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		synced := node.synced(ctx)
		if !synced {
			logger.Printf("group.Synced(%s) => %t", node.group.GenesisId(), synced)
			continue
		}
		sessions := node.listPreparedSessions(ctx)
		results := make([]<-chan error, len(sessions))
		for i, s := range sessions {
			threshold := node.threshold + 1
			signers, err := node.store.ListSessionPreparedMembers(ctx, s.Id, threshold)
			if err != nil {
				panic(err)
			}
			if len(signers) != threshold && s.Operation != OperationTypeKeygenInput {
				panic(fmt.Sprintf("ListSessionPreparedMember(%s, %d) => %d", s.Id, threshold, len(signers)))
			}
			results[i] = node.queueOperation(ctx, s.AsOperation(), node.GetPartySlice())
		}
		for _, res := range results {
			if res == nil {
				continue
			}
			if err := <-res; err != nil {
				panic(err)
			}
		}
	}
}

func (node *Node) listPreparedSessions(ctx context.Context) []*store.Session {
	parallelization := runtime.NumCPU() * (len(node.GetMembers())/16 + 1)

	var sessions []*store.Session
	prepared, err := node.store.ListPreparedSessions(ctx, parallelization*4)
	if err != nil {
		panic(err)
	}
	for _, s := range prepared {
		if s.CreatedAt.Add(SessionTimeout).Before(time.Now()) {
			err = node.store.FailSession(ctx, s.Id)
			logger.Printf("store.FailSession(%s, listPreparedSessions) => %v", s.Id, err)
			if err != nil {
				panic(err)
			}
			continue
		}
		sessions = append(sessions, s)
		if len(sessions) == parallelization {
			break
		}
	}
	return sessions
}

func (node *Node) loopPendingSessions(ctx context.Context) {
	for {
		time.Sleep(3 * time.Second)
		synced := node.synced(ctx)
		if !synced {
			logger.Printf("group.Synced(%s) => %t", node.group.GenesisId(), synced)
			continue
		}
		sessions, err := node.store.ListPendingSessions(ctx, 64)
		if err != nil {
			panic(err)
		}

		for _, s := range sessions {
			op := s.AsOperation()
			switch op.Type {
			case OperationTypeKeygenInput:
				op.Extra = common.DecodeHexOrPanic(op.Public)
				op.Type = OperationTypeKeygenOutput
			case OperationTypeSignInput:
				holder, share, path, err := node.readKeyByFingerPath(ctx, op.Public)
				if err != nil {
					panic(err)
				}
				signed, sig := node.verifySessionSignature(ctx, holder, op.Extra, share, path)
				if signed {
					op.Extra = sig
				} else {
					op.Extra = nil
				}
				op.Type = OperationTypeSignOutput
			default:
				panic(op.Id)
			}
			traceId := fmt.Sprintf("SESSION:%s:SIGNER:%s:RESULT", op.Id, string(node.id))

			extra := []byte{op.Type}
			extra = append(extra, op.IdBytes()...)
			extra = append(extra, op.Extra...)
			err := node.sendTransactionToGroupUntilSufficient(ctx, extra, traceId)
			logger.Printf("node.sendTransactionToGroupUntilSufficient(%x %s) => %v", extra, traceId, err)
			if err != nil {
				break
			}
			err = node.store.MarkSessionDone(ctx, op.Id)
			logger.Printf("node.MarkSessionDone(%v) => %v", op, err)
			if err != nil {
				break
			}
		}
	}
}

func (node *Node) acceptIncomingMessages(ctx context.Context) {
	for {
		mm, err := node.network.ReceiveMessage(ctx)
		logger.Debugf("network.ReceiveMessage() => %s %x %s %v", mm.Peer, mm.Data, mm.CreatedAt, err)
		if err != nil {
			panic(err)
		}
		sessionId, msg, err := unmarshalSessionMessage(mm.Data)
		logger.Verbosef("node.acceptIncomingMessages(%x, %d) => %s %s %x", sessionId, msg.RoundNumber, mm.Peer, mm.CreatedAt, msg.SSID)
		if err != nil {
			continue
		}
		if msg.SSID == nil {
			continue
		}
		if msg.From != party.ID(mm.Peer) {
			continue
		}
		if !msg.IsFor(node.id) {
			continue
		}
		mps := node.getSession(sessionId)
		// TODO verify msg signature by sender public key
		mps.incoming <- msg
		if msg.RoundNumber != MPCFirstMessageRound {
			continue
		}

		id := uuid.Must(uuid.FromBytes(sessionId))
		r, err := node.store.ReadSession(ctx, id.String())
		if err != nil {
			panic(err)
		}
		if r == nil {
			continue
		}
		threshold := node.threshold + 1
		signers, err := node.store.ListSessionPreparedMembers(ctx, r.Id, threshold)
		if err != nil {
			panic(err)
		}
		if len(signers) < threshold {
			continue
		}
		if r.State == common.RequestStateInitial {
			node.queueOperation(ctx, &common.Operation{
				Id:     r.Id,
				Type:   r.Operation,
				Public: r.Public,
				Extra:  common.DecodeHexOrPanic(r.Extra),
			}, signers)
		} else {
			rm := &protocol.Message{SSID: sessionId, From: node.id, To: party.ID(mm.Peer)}
			rmb := marshalSessionMessage(sessionId, rm)
			err := node.network.QueueMessage(ctx, mm.Peer, rmb)
			logger.Verbosef("network.QueueMessage(%x, %d) => %s %v", mps.id, msg.RoundNumber, id, err)
		}
	}
}

func (node *Node) queueOperation(ctx context.Context, op *common.Operation, members []party.ID) <-chan error {
	node.mutex.Lock()
	defer node.mutex.Unlock()

	if node.operations[op.Id] {
		return nil
	}
	node.operations[op.Id] = true

	res := make(chan error)
	go func() { res <- node.startOperation(ctx, op, members) }()
	return res
}

func (node *Node) handlerLoop(ctx context.Context, start round.Session, sessionId []byte, roundTimeout time.Duration) (any, error) {
	logger.Printf("node.handlerLoop(%x) => %x", sessionId, start.SSID())
	h, err := protocol.NewMultiHandler(start)
	if err != nil {
		return nil, err
	}
	mps := node.getSession(sessionId)
	mps.members = start.PartyIDs()

	res, err := node.loopMultiPartySession(ctx, mps, h, roundTimeout)
	missing := mps.missing(node.id)
	logger.Printf("node.loopMultiPartySession(%x, %d) => %v with %v missing", mps.id, mps.round, err, missing)
	return res, err
}

func (node *Node) loopMultiPartySession(ctx context.Context, mps *MultiPartySession, h protocol.Handler, roundTimeout time.Duration) (any, error) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				return h.Result()
			}
			msb := marshalSessionMessage(mps.id, msg)
			for _, id := range mps.members {
				if !msg.IsFor(id) {
					continue
				}
				err := node.network.QueueMessage(ctx, string(id), msb)
				logger.Verbosef("network.QueueMessage(%x, %d) => %s %v", mps.id, msg.RoundNumber, id, err)
			}
			mps.advance(msg)
			mps.process(ctx, h, node.store)
		case msg := <-mps.incoming:
			logger.Verbosef("network.incoming(%x, %d) %s", mps.id, msg.RoundNumber, msg.From)
			if !mps.findMember(msg.From) {
				continue
			}
			if bytes.Equal(mps.id, msg.SSID) {
				return nil, fmt.Errorf("node.handlerLoop(%x) expired from %s", mps.id, msg.From)
			}
			mps.receive(msg)
			mps.process(ctx, h, node.store)
		case <-time.After(roundTimeout):
			return nil, fmt.Errorf("node.handlerLoop(%x) timeout", mps.id)
		}
	}
}

type MultiPartySession struct {
	id       []byte
	members  []party.ID
	incoming chan *protocol.Message
	received map[round.Number][]*protocol.Message
	accepted map[round.Number][]*protocol.Message
	round    round.Number
}

func (mps *MultiPartySession) findMember(id party.ID) bool {
	for _, m := range mps.members {
		if m == id {
			return true
		}
	}
	return false
}

func (mps *MultiPartySession) missing(self party.ID) []party.ID {
	var missing []party.ID
	accepted := mps.accepted[mps.round]
	for _, id := range mps.members {
		if id == self {
			continue
		}
		if !slices.ContainsFunc(accepted, func(m *protocol.Message) bool {
			return m.From == id
		}) {
			missing = append(missing, id)
		}
	}
	return missing
}

func (mps *MultiPartySession) advance(msg *protocol.Message) {
	logger.Printf("MultiPartySession.advance(%x, %d) => %d", mps.id, mps.round, msg.RoundNumber)
	if mps.round < msg.RoundNumber {
		mps.round = msg.RoundNumber
	}
}

func (mps *MultiPartySession) receive(msg *protocol.Message) {
	mps.received[msg.RoundNumber] = append(mps.received[msg.RoundNumber], msg)
}

func (mps *MultiPartySession) process(ctx context.Context, h protocol.Handler, store *store.SQLite3Store) {
	for i, msg := range mps.received[mps.round] {
		if msg == nil || !h.CanAccept(msg) {
			continue
		}
		logger.Verbosef("handler.CanAccept(%x, %d) => %s", mps.id, msg.RoundNumber, msg.From)
		accepted := h.Accept(msg)
		logger.Verbosef("handler.Accept(%x, %d) => %s %t", mps.id, msg.RoundNumber, msg.From, accepted)
		if !accepted {
			continue
		}
		sid := uuid.Must(uuid.FromBytes(mps.id)).String()
		extra := common.MarshalPanic(msg)
		err := store.WriteSessionWorkIfNotExist(ctx, sid, string(msg.From), int(msg.RoundNumber), extra)
		logger.Verbosef("store.WriteSessionWorkIfNotExist(%s, %s, %d) => %v", sid, msg.From, msg.RoundNumber, err)
		if err != nil {
			panic(err)
		}
		mps.accepted[msg.RoundNumber] = append(mps.accepted[msg.RoundNumber], msg)
		mps.received[mps.round][i] = nil
	}
}

func (node *Node) getSession(sessionId []byte) *MultiPartySession {
	node.mutex.Lock()
	defer node.mutex.Unlock()

	sid := hex.EncodeToString(sessionId)
	session := node.sessions[sid]

	members := node.GetMembers()
	if session == nil {
		size := len(members) * len(members)
		session = &MultiPartySession{
			id:       sessionId,
			round:    MPCFirstMessageRound,
			incoming: make(chan *protocol.Message, size),
			received: make(map[round.Number][]*protocol.Message),
			accepted: make(map[round.Number][]*protocol.Message),
		}
		node.sessions[sid] = session
	}
	return session
}

func marshalSessionMessage(sessionId []byte, msg *protocol.Message) []byte {
	if len(sessionId) > 32 {
		panic(hex.EncodeToString(sessionId))
	}
	msb := []byte{byte(len(sessionId))}
	msb = append(msb, sessionId...)
	return append(msb, common.MarshalPanic(msg)...)
}

func unmarshalSessionMessage(b []byte) ([]byte, *protocol.Message, error) {
	if len(b) < 16 {
		return nil, nil, fmt.Errorf("unmarshalSessionMessage(%x) short", b)
	}
	if len(b[1:]) <= int(b[0]) {
		return nil, nil, fmt.Errorf("unmarshalSessionMessage(%x) short", b)
	}
	sessionId := b[1 : 1+b[0]]
	var msg protocol.Message
	err := msg.UnmarshalBinary(b[1+b[0]:])
	return sessionId, &msg, err
}
