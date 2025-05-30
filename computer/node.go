package computer

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	solanaApp "github.com/MixinNetwork/safe/apps/solana"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/safe/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
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

	solana *solanaApp.Client
	mixin  *mixin.Client
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
		solana:     solanaApp.NewClient(conf.SolanaRPC),
	}

	members := node.GetMembers()
	mgt := conf.MTG.Genesis.Threshold
	if mgt < conf.Threshold || mgt < len(members)*2/3+1 {
		panic(fmt.Errorf("%d/%d/%d", conf.Threshold, mgt, len(members)))
	}

	return node
}

func (node *Node) Boot(ctx context.Context, version string) {
	go node.bootObserver(ctx, version)
	go node.bootSigner(ctx)

	mtg := node.getMTGAddress(ctx)
	logger.Printf("node.Boot(%s, %d, %s)", node.id, node.Index(), mtg.String())
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

func (node *Node) SafeUser() *bot.SafeUser {
	return &bot.SafeUser{
		UserId:            node.conf.MTG.App.AppId,
		SessionId:         node.conf.MTG.App.SessionId,
		ServerPublicKey:   node.conf.MTG.App.ServerPublicKey,
		SessionPrivateKey: node.conf.MTG.App.SessionPrivateKey,
		SpendPrivateKey:   node.conf.MTG.App.SpendPrivateKey,
	}
}

func (node *Node) readRequestNumber(ctx context.Context, key string) (int64, error) {
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil || val == "" {
		return 0, err
	}
	num, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		panic(err)
	}
	return num, nil
}

func (node *Node) writeRequestNumber(ctx context.Context, key string, sequence int64) error {
	return node.store.WriteProperty(ctx, key, fmt.Sprintf("%d", sequence))
}

func (node *Node) readSolanaBlockCheckpoint(ctx context.Context) (int64, error) {
	height, err := node.readRequestNumber(ctx, store.SolanaScanHeightKey)
	if err != nil || height == 0 {
		return 315360000, err
	}
	return height, nil
}

func (node *Node) readPropertyAsTime(ctx context.Context, key string) time.Time {
	val, err := node.store.ReadProperty(ctx, key)
	if err != nil {
		panic(err)
	}
	if val == "" {
		return time.Unix(0, node.conf.Timestamp)
	}
	ts, err := time.Parse(time.RFC3339Nano, val)
	if err != nil {
		panic(val)
	}
	return ts
}

func (node *Node) writeRequestTime(ctx context.Context, key string, offset time.Time) error {
	return node.store.WriteProperty(ctx, key, offset.Format(time.RFC3339Nano))
}
