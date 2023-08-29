package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) sendKeygenBackup(ctx context.Context, op *common.Operation, share []byte) error {
	if node.conf.SaverAPI == "" {
		return nil
	}

	sid := uuid.Must(uuid.NewV4())
	secret := crypto.NewHash([]byte(node.saverKey.String() + sid.String()))
	secret = crypto.NewHash(secret[:])

	share = append(sid.Bytes(), share...)
	share = common.AESEncrypt(secret[:], share, sid.String())
	public := common.AESEncrypt(secret[:], op.Encode(), op.Id)
	data := map[string]string{
		"id":         sid.String(),
		"node_id":    string(node.id),
		"session_id": op.Id,
		"public":     base64.RawURLEncoding.EncodeToString(public),
		"share":      base64.RawURLEncoding.EncodeToString(share),
	}

	msg := data["id"] + data["node_id"] + data["session_id"]
	msg = msg + data["public"] + data["share"]
	data["signature"] = node.saverKey.Sign([]byte(msg)).String()

	msg = string(common.MarshalJSONOrPanic(data))
	reader := strings.NewReader(msg)
	resp, err := node.backupClient.Post(node.conf.SaverAPI, "application/json", reader)
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("backupClient.Post(%s, %v) => %v %v", node.conf.SaverAPI, op, resp, err)
	}
	defer resp.Body.Close()

	var body struct {
		Id   string `json:"id"`
		Size int    `json:"size"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil || body.Id != sid.String() || body.Size != len(msg) {
		return fmt.Errorf("backupClient.Post(%s, %v) => %v %v", node.conf.SaverAPI, op, body, err)
	}
	return nil
}
