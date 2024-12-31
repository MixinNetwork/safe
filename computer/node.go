package computer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
	solana "github.com/gagliardetto/solana-go"
)

type Node struct {
	id        party.ID
	threshold int

	conf       *Configuration
	group      *mtg.Group
	network    Network
	mutex      *sync.Mutex
	sessions   map[string]*MultiPartySession
	operations map[string]bool
	store      *store.SQLite3Store

	mixin        *mixin.Client
	backupClient *http.Client
	saverKey     *crypto.Key
}

func NewNode(store *store.SQLite3Store, group *mtg.Group, network Network, conf *Configuration, mixin *mixin.Client) *Node {
	node := &Node{
		id:         party.ID(conf.MTG.App.AppId),
		threshold:  conf.Threshold,
		conf:       conf,
		group:      group,
		network:    network,
		mutex:      new(sync.Mutex),
		sessions:   make(map[string]*MultiPartySession),
		operations: make(map[string]bool),
		store:      store,
		mixin:      mixin,
		backupClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	priv, err := crypto.KeyFromString(conf.SaverKey)
	if err != nil {
		panic(conf.SaverKey)
	}
	logger.Printf("node.saverKey %s", priv.Public())
	node.saverKey = &priv

	members := node.GetMembers()
	if mgt := conf.MTG.Genesis.Threshold; mgt < conf.Threshold || mgt < len(members)*2/3+1 {
		panic(fmt.Errorf("%d/%d/%d", conf.Threshold, mgt, len(members)))
	}

	return node
}

func (node *Node) Boot(ctx context.Context) {
	node.bootComputer(ctx)
	node.bootObserver(ctx)
	node.bootSigner(ctx)
	logger.Printf("node.Boot(%s, %d)", node.id, node.Index())
}

func (node *Node) Index() int {
	index := node.findMember(string(node.id))
	if index < 0 {
		panic(node.id)
	}
	return index
}

func (node *Node) findMember(m string) int {
	return slices.Index(node.GetMembers(), m)
}

func (node *Node) synced(ctx context.Context) bool {
	if common.CheckTestEnvironment(ctx) {
		return true
	}
	// TODO all nodes send group timestamp to others, and not synced
	// if one of them has a big difference
	return node.group.Synced(ctx)
}

func (node *Node) GetMembers() []string {
	ms := make([]string, len(node.conf.MTG.Genesis.Members))
	copy(ms, node.conf.MTG.Genesis.Members)
	sort.Strings(ms)
	return ms
}

func (node *Node) IsMember(id string) bool {
	return slices.Contains(node.GetMembers(), id)
}

func (node *Node) IsFromGroup(senders []string) bool {
	members := node.GetMembers()
	if len(members) != len(senders) {
		return false
	}
	sort.Strings(senders)
	return slices.Equal(members, senders)
}

func (node *Node) GetPartySlice() party.IDSlice {
	members := node.GetMembers()
	ms := make(party.IDSlice, len(members))
	for i, id := range members {
		ms[i] = party.ID(id)
	}
	return ms
}

func (node *Node) bootComputer(ctx context.Context) {
	go node.unsignedCallsLoop(ctx)
}

func (node *Node) unsignedCallsLoop(ctx context.Context) {
	for {
		err := node.processUnsignedCalls(ctx)
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Minute)
	}
}

func (node *Node) processUnsignedCalls(ctx context.Context) error {
	members := node.GetMembers()
	threshold := node.conf.MTG.Genesis.Threshold

	calls, err := node.store.ListUnsignedCalls(ctx)
	if err != nil {
		return err
	}
	for _, call := range calls {
		now := time.Now()
		if call.RequestSignerAt.Time.Add(20 * time.Minute).After(now) {
			continue
		}
		req, err := node.store.ReadRequest(ctx, call.Superior)
		if err != nil {
			return err
		}

		createdAt := now
		if call.RequestSignerAt.Valid {
			createdAt = call.RequestSignerAt.Time
		}
		id := common.UniqueId(call.RequestId, createdAt.String())
		id = common.UniqueId(id, fmt.Sprintf("MTG:%v:%d", members, threshold))
		session := &store.Session{
			Id:         id,
			RequestId:  call.RequestId,
			MixinHash:  req.MixinHash.String(),
			MixinIndex: req.Output.OutputIndex,
			Index:      0,
			Operation:  OperationTypeSignInput,
			Public:     hex.EncodeToString(common.Fingerprint(call.Public)),
			Extra:      call.Message,
			CreatedAt:  createdAt,
		}
		err = node.store.RequestSignerSignForCall(ctx, call, []*store.Session{session})
		if err != nil {
			return err
		}
	}
	return nil
}

func (node *Node) failRequest(ctx context.Context, req *store.Request, assetId string) ([]*mtg.Transaction, string) {
	logger.Printf("node.failRequest(%v, %s)", req, assetId)
	err := node.store.FailRequest(ctx, req, assetId, nil)
	if err != nil {
		panic(err)
	}
	return nil, assetId
}

func (node *Node) readStorageExtraFromObserver(ctx context.Context, ref crypto.Hash) []byte {
	if common.CheckTestEnvironment(ctx) {
		val, err := node.store.ReadProperty(ctx, ref.String())
		if err != nil {
			panic(ref.String())
		}
		raw, err := base64.RawURLEncoding.DecodeString(val)
		if err != nil {
			panic(ref.String())
		}
		return raw
	}

	ver, err := node.group.ReadKernelTransactionUntilSufficient(ctx, ref.String())
	if err != nil {
		panic(ref.String())
	}

	return ver.Extra
}
func (node *Node) solanaClient() *solanaApp.Client {
	return solanaApp.NewClient(node.conf.SolanaRPC, node.conf.SolanaWsRPC)
}

func (node *Node) solanaAccount() solana.PublicKey {
	return solana.MustPrivateKeyFromBase58(node.conf.SolanaKey).PublicKey()
}

func (node *Node) safeUser() *bot.SafeUser {
	return &bot.SafeUser{
		UserId:            node.conf.MTG.App.AppId,
		SessionId:         node.conf.MTG.App.SessionId,
		ServerPublicKey:   node.conf.MTG.App.ServerPublicKey,
		SessionPrivateKey: node.conf.MTG.App.SessionPrivateKey,
		SpendPrivateKey:   node.conf.MTG.App.SpendPrivateKey,
	}
}

func (node *Node) readRequestTime(ctx context.Context, key string) (time.Time, error) {
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil || val == "" {
		return time.Unix(0, node.conf.Timestamp), err
	}
	return time.Parse(time.RFC3339Nano, val)
}

func (node *Node) writeRequestTime(ctx context.Context, key string) error {
	return node.store.WriteProperty(ctx, key, time.Now().Format(time.RFC3339Nano))
}

func (node *Node) readRequestSequence(ctx context.Context, key string) (uint64, error) {
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil || val == "" {
		return 0, err
	}
	num, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		panic(err)
	}
	return num, nil
}

func (node *Node) writeRequestSequence(ctx context.Context, key string, sequence uint64) error {
	return node.store.WriteProperty(ctx, key, fmt.Sprintf("%d", sequence))
}
