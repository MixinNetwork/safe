package mtg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/safe/util"
)

func GetKernelTransaction(rpc, hash string) (*common.VersionedTransaction, string, error) {
	raw, err := callMixinRPC(rpc, "gettransaction", []any{hash})
	if err != nil || raw == nil {
		return nil, "", err
	}
	var signed struct {
		Hex      string `json:"hex"`
		Snapshot string `json:"snapshot"`
	}
	err = json.Unmarshal(raw, &signed)
	if err != nil {
		return nil, "", err
	}
	b, err := hex.DecodeString(signed.Hex)
	if err != nil {
		return nil, "", err
	}
	ver, err := common.UnmarshalVersionedTransaction(b)
	if err != nil {
		return nil, "", err
	}
	if actual := ver.PayloadHash().String(); actual != hash {
		return nil, "", fmt.Errorf("unexpected kernel transaction hash %s, expected %s", actual, hash)
	}
	return ver, signed.Snapshot, nil
}

func callMixinRPC(node, method string, params []any) ([]byte, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	body, err := json.Marshal(map[string]any{
		"method": method,
		"params": params,
	})
	if err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", node, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer util.CloseOrPanic(resp.Body)
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("callMixinRPC(%s, %s, %s) => HTTP %d %s", node, method, params, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var result struct {
		Data  any `json:"data"`
		Error any `json:"error"`
	}
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	err = dec.Decode(&result)
	if err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("callMixinRPC(%s, %s, %s) => %v", node, method, params, result.Error)
	}
	if result.Data == nil {
		return nil, nil
	}

	return json.Marshal(result.Data)
}
