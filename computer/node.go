package computer

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/MixinNetwork/trusted-group/mtg"
	"github.com/fox-one/mixin-sdk-go/v2"
)

type Node struct {
	id        party.ID
	threshold int

	conf       *Configuration
	group      *mtg.Group
	network    Network
	aesKey     [32]byte
	mutex      *sync.Mutex
	sessions   map[string]*MultiPartySession
	operations map[string]bool
	store      *store.SQLite3Store

	keeper       *mtg.Configuration
	mixin        *mixin.Client
	backupClient *http.Client
	saverKey     *crypto.Key
}

func NewNode(store *store.SQLite3Store, group *mtg.Group, network Network, conf *Configuration, keeper *mtg.Configuration, mixin *mixin.Client) *Node {
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
		keeper:     keeper,
		mixin:      mixin,
		backupClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	node.aesKey = common.ECDHEd25519(conf.SharedKey, conf.PublicKey)

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
	go node.loopBackup(ctx)
	go node.loopInitialSessions(ctx)
	go node.loopPreparedSessions(ctx)
	go node.loopPendingSessions(ctx)
	go node.acceptIncomingMessages(ctx)
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

func (node *Node) failRequest(ctx context.Context, req *store.Request, assetId string) ([]*mtg.Transaction, string) {
	logger.Printf("node.failRequest(%v, %s)", req, assetId)
	err := node.store.FailRequest(ctx, req, assetId, nil)
	if err != nil {
		panic(err)
	}
	return nil, assetId
}
