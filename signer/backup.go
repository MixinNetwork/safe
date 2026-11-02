package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/util"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) sendKeygenBackup(ctx context.Context, op *common.Operation, share []byte) (bool, error) {
	sid := uuid.Must(uuid.NewV4())
	secret := crypto.Sha256Hash([]byte(node.saverKey.String() + sid.String()))
	secret = crypto.Sha256Hash(secret[:])

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
	hash := crypto.Sha256Hash([]byte(msg))
	data["signature"] = node.saverKey.Sign(hash).String()

	msg = string(common.MarshalJSONOrPanic(data))
	reader := strings.NewReader(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, node.conf.SaverAPI, reader)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := node.backupClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("backupClient.Post(%s, %v) => %v %v", node.conf.SaverAPI, op, resp, err)
	}
	defer util.CloseOrPanic(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("backupClient.Post(%s, %v) => %s", node.conf.SaverAPI, op, resp.Status)
	}

	var body struct {
		Id   string `json:"id"`
		Size int    `json:"size"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil || body.Id != sid.String() || body.Size != len(msg) {
		return false, fmt.Errorf("backupClient.Post(%s, %v) => %v %v", node.conf.SaverAPI, op, body, err)
	}
	return true, nil
}
