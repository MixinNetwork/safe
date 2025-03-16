package computer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"runtime"
	"slices"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/signer/protocol"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) bootSigner(ctx context.Context) {
	go node.loopInitialSessions(ctx)
	go node.loopPreparedSessions(ctx)
	go node.loopPendingSessions(ctx)
	go node.acceptIncomingMessages(ctx)
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
			extra := []byte{OperationTypeSignPrepare}
			extra = append(extra, uuid.Must(uuid.FromString(s.Id)).Bytes()...)
			extra = append(extra, PrepareExtra...)
			err := node.sendTransactionToGroupUntilSufficient(ctx, extra, node.conf.AssetId, traceId, nil)
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
			results[i] = node.queueOperation(ctx, s.AsOperation(), signers)
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
		if s.CreatedAt.Add(SessionTimeout).Before(time.Now().UTC()) {
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
				public, share, path, err := node.readKeyByFingerPath(ctx, op.Public)
				logger.Printf("node.readKeyByFingerPath(%s) => %s %v", op.Public, public, err)
				if err != nil || public == "" {
					panic(fmt.Errorf("node.readKeyByFingerPath(%s) => %s %v", op.Public, public, err))
				}
				call, err := node.store.ReadSystemCallByRequestId(ctx, s.RequestId, 0)
				if err != nil {
					panic(err)
				}
				signed, sig := node.verifySessionSignature(common.DecodeHexOrPanic(call.Message), op.Extra, share, path)
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
			err := node.sendTransactionToGroupUntilSufficient(ctx, extra, node.conf.AssetId, traceId, nil)
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

func (node *Node) processSignerKeygenResults(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeKeygenOutput {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	sid := uuid.FromBytesOrNil(extra[:16]).String()
	public := extra[16:]

	s, err := node.store.ReadSession(ctx, sid)
	logger.Printf("store.ReadSession(%s) => %v %v", sid, s, err)
	if err != nil {
		panic(err)
	}
	fp := hex.EncodeToString(common.Fingerprint(hex.EncodeToString(public)))
	key, _, err := node.store.ReadKeyByFingerprint(ctx, fp)
	logger.Printf("store.ReadKeyByFingerprint(%s) => %s %v", fp, key, err)
	if err != nil || key == "" {
		panic(err)
	}
	if key != hex.EncodeToString(public) {
		panic(key)
	}

	sender := req.Output.Senders[0]
	err = node.store.WriteSessionSignerIfNotExist(ctx, s.Id, sender, public, req.Output.SequencerCreatedAt, sender == string(node.id))
	if err != nil {
		panic(fmt.Errorf("store.WriteSessionSignerIfNotExist(%v) => %v", s, err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err))
	}
	finished, sig := node.verifySessionSignerResults(ctx, s, signers)
	logger.Printf("node.verifySessionSignerResults(%v, %d) => %t %x", s, len(signers), finished, sig)
	if !finished {
		return node.failRequest(ctx, req, "")
	}
	if l := len(signers); l <= node.threshold {
		panic(s.Id)
	}

	valid := node.verifySessionHolder(ctx, hex.EncodeToString(public))
	logger.Printf("node.verifySessionHolder(%x) => %t", public, valid)
	if !valid {
		return nil, ""
	}

	err = node.store.MarkKeyConfirmedWithRequest(ctx, req, hex.EncodeToString(public))
	if err != nil {
		panic(fmt.Errorf("store.MarkKeyConfirmedWithRequest(%v) => %v", req, err))
	}
	return nil, ""
}

func (node *Node) processSignerKeygenRequests(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleObserver {
		panic(req.Role)
	}
	if req.Action != OperationTypeKeygenInput {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	if len(extra) != 1 {
		return node.failRequest(ctx, req, "")
	}
	count, err := node.store.CountKeys(ctx)
	logger.Printf("store.CountKeys() => %v %d:%d:%d", err, count, extra[0], node.conf.MPCKeyNumber)
	if err != nil {
		panic(err)
	}
	if int(extra[0]) != count || count >= node.conf.MPCKeyNumber {
		return node.failRequest(ctx, req, "")
	}

	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold
	id := common.UniqueId(req.Id, fmt.Sprintf("OperationTypeKeygenInput:%d", count))
	id = common.UniqueId(id, fmt.Sprintf("MTG:%v:%d", members, threshold))
	sessions := []*store.Session{{
		Id:         id,
		RequestId:  req.Id,
		MixinHash:  req.MixinHash.String(),
		MixinIndex: req.Output.OutputIndex,
		Index:      0,
		Operation:  OperationTypeKeygenInput,
		CreatedAt:  req.CreatedAt,
	}}
	err = node.store.WriteSessionsWithRequest(ctx, req, sessions, false)
	if err != nil {
		panic(fmt.Errorf("store.WriteSessionsWithRequest(%v) => %v", req, err))
	}
	return nil, ""
}

func (node *Node) processSignerPrepare(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignPrepare {
		panic(req.Action)
	}

	extra := req.ExtraBytes()
	session := uuid.Must(uuid.FromBytes(extra[:16])).String()
	extra = extra[16:]
	if !bytes.Equal(extra, PrepareExtra) {
		logger.Printf("invalid prepare extra: %s", string(extra))
		return node.failRequest(ctx, req, "")
	}

	s, err := node.store.ReadSession(ctx, session)
	if err != nil || s == nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v %v", session, s, err))
	}
	if s.PreparedAt.Valid {
		logger.Printf("session %s is prepared", s.Id)
		return node.failRequest(ctx, req, "")
	}

	err = node.store.PrepareSessionSignerIfNotExist(ctx, s.Id, req.Output.Senders[0], req.Output.SequencerCreatedAt)
	logger.Printf("store.PrepareSessionSignerIfNotExist(%s %s %s) => %v", s.Id, node.id, req.Output.Senders[0], err)
	if err != nil {
		panic(fmt.Errorf("store.PrepareSessionSignerIfNotExist(%v) => %v", s, err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	logger.Printf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err)
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %v", s.Id, err))
	}
	if len(signers) <= node.threshold {
		logger.Printf("insufficient prepared signers: %d %d", len(signers), node.threshold)
		return node.failRequest(ctx, req, "")
	}
	err = node.store.MarkSessionPreparedWithRequest(ctx, req, s.Id, req.Output.SequencerCreatedAt)
	if err != nil {
		panic(fmt.Errorf("node.MarkSessionPreparedWithRequest(%s %v) => %v", s.Id, req.Output.SequencerCreatedAt, err))
	}
	return nil, ""
}

func (node *Node) processSignerSignatureResponse(ctx context.Context, req *store.Request) ([]*mtg.Transaction, string) {
	logger.Printf("node.processSignerSignatureResponse(%s)", string(node.id))
	if req.Role != RequestRoleSigner {
		panic(req.Role)
	}
	if req.Action != OperationTypeSignOutput {
		panic(req.Action)
	}
	extra := req.ExtraBytes()
	sid := uuid.FromBytesOrNil(extra[:16]).String()
	signature := extra[16:]
	s, err := node.store.ReadSession(ctx, sid)
	if err != nil || s == nil {
		panic(fmt.Errorf("store.ReadSession(%s) => %v %v", sid, s, err))
	}
	call, err := node.store.ReadSystemCallByRequestId(ctx, s.RequestId, 0)
	if err != nil || call == nil {
		panic(fmt.Errorf("store.ReadSystemCallByRequestId(%s) => %v %v", s.RequestId, call, err))
	}
	if call.State == common.RequestStateFailed || call.Signature.Valid {
		logger.Printf("invalid call %s: %d %s", call.RequestId, call.State, call.Signature.String)
		return node.failRequest(ctx, req, "")
	}

	self := len(req.Output.Senders) == 1 && req.Output.Senders[0] == string(node.id)
	err = node.store.UpdateSessionSigner(ctx, s.Id, req.Output.Senders[0], signature, req.Output.SequencerCreatedAt, self)
	if err != nil {
		panic(fmt.Errorf("store.UpdateSessionSigner(%s %s) => %v", s.Id, req.Output.Senders[0], err))
	}
	signers, err := node.store.ListSessionSignerResults(ctx, s.Id)
	logger.Printf("store.ListSessionSignerResults(%s) => %d", s.Id, len(signers))
	if err != nil {
		panic(fmt.Errorf("store.ListSessionSignerResults(%s) => %d %v", s.Id, len(signers), err))
	}
	finished, sig := node.verifySessionSignerResults(ctx, s, signers)
	logger.Printf("node.verifySessionSignerResults(%v, %d) => %t %x", s, len(signers), finished, sig)
	if !finished {
		return node.failRequest(ctx, req, "")
	}
	if l := len(signers); l <= node.threshold {
		panic(s.Id)
	}
	extra = common.DecodeHexOrPanic(s.Extra)
	if s.State == common.RequestStateInitial && s.PreparedAt.Valid {
		// this could happend only after crash or not commited
		err = node.store.MarkSessionPending(ctx, s.Id, s.Public, extra)
		logger.Printf("store.MarkSessionPending(%v, processSignerResult) => %x %v\n", s, extra, err)
		if err != nil {
			panic(err)
		}
	}
	_, share, path, err := node.readKeyByFingerPath(ctx, s.Public)
	logger.Printf("node.readKeyByFingerPath(%s) => %v", s.Public, err)
	if err != nil {
		panic(err)
	}
	valid, vsig := node.verifySessionSignature(common.DecodeHexOrPanic(call.Message), sig, share, path)
	logger.Printf("node.verifySessionSignature(%v, %x) => %t", s, sig, valid)
	if !valid || !bytes.Equal(sig, vsig) {
		panic(hex.EncodeToString(vsig))
	}

	if common.CheckTestEnvironment(ctx) {
		key := "SIGNER:" + sid
		val, err := node.store.ReadProperty(ctx, key)
		if err != nil {
			panic(err)
		}
		if val == "" {
			extra := []byte{OperationTypeSignOutput}
			extra = append(extra, signature...)
			err = node.store.WriteProperty(ctx, key, hex.EncodeToString(extra))
			if err != nil {
				panic(err)
			}
		}
	}
	err = node.store.AttachSystemCallSignatureWithRequest(ctx, req, call, s.Id, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		panic(fmt.Errorf("store.AttachSystemCallSignatureWithRequest(%s %v) => %v", s.Id, call, err))
	}

	return nil, ""
}
