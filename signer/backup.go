package signer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/MixinNetwork/safe/common"
	"github.com/gofrs/uuid"
)

func (node *Node) sendKeygenBackup(ctx context.Context, op *common.Operation, share []byte) error {
	if node.conf.BackupAPI == "" {
		return nil
	}
	key := common.DecodeHexOrPanic(node.conf.BackupKey)
	if len(key) != 32 {
		panic(node.conf.BackupKey)
	}

	oid := uuid.Must(uuid.FromString(op.Id))
	share = append(oid.Bytes(), share...)
	sid := uuid.Must(uuid.NewV4())
	share = append(sid.Bytes(), share...)
	share = common.AESEncrypt(key, share, sid.String())

	public := common.AESEncrypt(key, op.Encode(), op.Id)
	data := common.MarshalJSONOrPanic(map[string]any{
		"id":         sid.String(),
		"node_id":    node.id,
		"session_id": op.Id,
		"public":     common.Base91Encode(public),
		"share":      common.Base91Encode(share),
	})

	resp, err := node.backupClient.Post(node.conf.BackupAPI, "application/json", bytes.NewReader(data))
	if err != nil || resp.StatusCode != 200 {
		return fmt.Errorf("backupClient.Post(%s, %v) => %v %v", node.conf.BackupAPI, op, resp, err)
	}
	defer resp.Body.Close()

	var body map[string]string
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil || body["id"] != sid.String() {
		return fmt.Errorf("backupClient.Post(%s, %v) => %v %v", node.conf.BackupAPI, op, body, err)
	}
	return nil
}
