package observer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client/v3"
)

const (
	NodeTypeKeeper = "keeper"
	NodeTypeSigner = "signer"
)

type AppInfo struct {
	Version string `json:"binary_version"`

	//keeper
	SignerBitcoinKeys    string `json:"signer_bitcoin_keys,omitempty"`
	SignerEthereumKeys   string `json:"signer_ethereum_keys,omitempty"`
	ObserverBitcoinKeys  string `json:"observer_bitcoin_keys,omitempty"`
	ObserverEthereumKeys string `json:"observer_ethereum_keys,omitempty"`
	InitialTxs           string `json:"initial_transactions,omitempty"`
	PendingTxs           string `json:"pending_transactions,omitempty"`
	DoneTxs              string `json:"done_transactions,omitempty"`
	FailedTxs            string `json:"failed_transactions,omitempty"`

	// signer
	InitialSessions string `json:"initial_sessions,omitempty"`
	PendingSessions string `json:"pending_sessions,omitempty"`
	FinalSessions   string `json:"final_sessions,omitempty"`
	GeneratedKeys   string `json:"generated_keys,omitempty"`
}

type MtgInfo struct {
	InitialTxs  string `json:"initial_transactions"`
	SignedTxs   string `json:"signed_transactions"`
	SnapshotTxs string `json:"snapshot_transactions"`
	MSKTOutputs string `json:"mskt_outputs"`

	// keeper
	LatestRequest string `json:"latest_request,omitempty"`
	BitcoinHeight string `json:"bitcoin_height,omitempty"`
	XINOutputs    string `json:"xin_outputs,omitempty"`

	// signer
	MSSTOutputs string `json:"msst_outputs,omitempty"`
}

type StatsInfo struct {
	Type string  `json:"type"`
	Mtg  MtgInfo `json:"mtg"`
	App  AppInfo `json:"app"`
}

func (s *StatsInfo) stringify() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type mixinBlazeHandler func(ctx context.Context, msg bot.MessageView, clientID string) error

func (f mixinBlazeHandler) OnMessage(ctx context.Context, msg bot.MessageView, clientID string) error {
	return f(ctx, msg, clientID)
}

func (f mixinBlazeHandler) OnAckReceipt(ctx context.Context, msg bot.MessageView, clientID string) error {
	return nil
}

func (f mixinBlazeHandler) SyncAck() bool {
	return true
}

func (node *Node) Blaze(ctx context.Context) {
	mixin := node.safeUser()
	for {
		client := bot.NewBlazeClient(mixin.UserId, mixin.SessionId, mixin.SessionPrivateKey)
		h := func(ctx context.Context, botMsg bot.MessageView, clientID string) error {
			err := node.handleMessage(ctx, botMsg)
			if err != nil {
				log.Printf("blaze.handleMessage() => %v", err)
				return err
			}
			return nil
		}
		if err := client.Loop(ctx, mixinBlazeHandler(h)); err != nil {
			log.Printf("client.Loop() => %#v", err)
			panic(err)
		}
		time.Sleep(time.Second)
	}
}

func (node *Node) handleMessage(ctx context.Context, bm bot.MessageView) error {
	if bm.ConversationId != node.conf.MonitorConversaionId {
		return nil
	}
	if bm.Category != bot.MessageCategoryPlainText {
		return nil
	}
	stats := parseNodeStats(bm.DataBase64)
	if stats == nil {
		return nil
	}
	str, err := stats.stringify()
	if err != nil {
		return err
	}
	return node.store.UpsertNodeStats(ctx, bm.UserId, stats.Type, str)
}

func parseNodeStats(dataBase64 string) *StatsInfo {
	rb, err := base64.RawURLEncoding.DecodeString(dataBase64)
	if err != nil {
		return nil
	}
	msg := string(rb)
	lines := strings.Split(msg, "\n")

	stats := &StatsInfo{
		Mtg: MtgInfo{},
		App: AppInfo{},
	}
	switch {
	case strings.HasPrefix(msg, "🧱🧱🧱🧱🧱 Keeper 🧱🧱🧱🧱🧱"):
		stats.Type = NodeTypeKeeper
	case strings.HasPrefix(msg, "📋📋📋📋📋 Signer 📋📋📋📋📋"):
		stats.Type = NodeTypeSigner
	default:
		return nil
	}

	for _, line := range lines {
		if line == "" {
			continue
		}
		items := strings.Split(line, ":")
		if len(items) != 2 {
			continue
		}
		key, value := strings.TrimSpace(items[0])[5:], strings.TrimSpace(items[1])
		switch key {
		case "Latest request":
			stats.Mtg.LatestRequest = value
		case "Bitcoin height":
			stats.Mtg.BitcoinHeight = value
		case "Initial Transactions":
			if stats.Type == NodeTypeSigner {
				stats.Mtg.InitialTxs = value
			} else {
				stats.App.InitialTxs = value
			}
		case "Signed Transactions":
			stats.Mtg.SignedTxs = value
		case "Snapshot Transactions":
			stats.Mtg.SnapshotTxs = value
		case "XIN Outputs":
			stats.Mtg.XINOutputs = value
		case "MSKT Outputs":
			stats.Mtg.MSKTOutputs = value
		case "MSST Outputs":
			stats.Mtg.MSSTOutputs = value
		case "Signer Bitcoin keys":
			stats.App.SignerBitcoinKeys = value
		case "Signer Ethereum keys":
			stats.App.SignerEthereumKeys = value
		case "Observer Bitcoin keys":
			stats.App.ObserverBitcoinKeys = value
		case "Pending Transactions":
			stats.App.PendingTxs = value
		case "Done Transactions":
			stats.App.DoneTxs = value
		case "Failed Transactions":
			stats.App.FailedTxs = value
		case "Initial sessions":
			stats.App.InitialSessions = value
		case "Pending sessions":
			stats.App.PendingSessions = value
		case "Final sessions":
			stats.App.FinalSessions = value
		case "Generated keys":
			stats.App.GeneratedKeys = value
		case "Binary version":
			stats.App.Version = value
		}
	}

	return stats
}
