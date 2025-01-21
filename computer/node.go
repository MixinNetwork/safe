package computer

import (
	"context"
	"encoding/base64"
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

	members := node.GetMembers()
	if mgt := conf.MTG.Genesis.Threshold; mgt < conf.Threshold || mgt < len(members)*2/3+1 {
		panic(fmt.Errorf("%d/%d/%d", conf.Threshold, mgt, len(members)))
	}

	return node
}

func (node *Node) Boot(ctx context.Context) {
	go node.bootObserver(ctx)
	go node.bootSigner(ctx)
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

func (node *Node) writeRequestTime(ctx context.Context, key string, offset time.Time) error {
	return node.store.WriteProperty(ctx, key, offset.Format(time.RFC3339Nano))
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
		return 313743624, err
	}
	return height, nil
}
