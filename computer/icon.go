package computer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"net/http"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/safe/common"
	"github.com/chai2010/webp"
	"github.com/disintegration/imaging"
	"github.com/fogleman/gg"
)

const size = 512

func readImageFromUrl(url string) (*image.NRGBA, error) {
	if url[len(url)-5:] == "=s128" {
		url = url[:len(url)-5] + "=s512"
	}
	res, err := http.Get(url)
	if err != nil || res.StatusCode != 200 {
		return nil, fmt.Errorf("http.Get(%s) => %v, %v", url, res, err)
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	icon512 := imaging.Resize(img, size, size, imaging.Lanczos)
	return icon512, nil
}

func applyCircleMask(img image.Image) image.Image {
	dc := gg.NewContext(size, size)
	dc.DrawRoundedRectangle(0, 0, size, size, size/2)
	dc.Clip()
	dc.DrawImage(img, 0, 0)
	return dc.Image()
}

func getWebpBase64(img image.Image) (string, error) {
	var buf bytes.Buffer
	err := webp.Encode(&buf, img, &webp.Options{
		Lossless: true,
		Exact:    true,
	})
	if err != nil {
		return "", err
	}
	base64Str := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/webp;base64," + base64Str, nil
}

func (node *Node) processAssetIcon(ctx context.Context, asset *bot.AssetNetwork) (string, error) {
	icon, err := readImageFromUrl(asset.IconURL)
	if err != nil {
		return "", err
	}
	if asset.AssetID != bot.XINAssetId {
		mark, _, err := image.Decode(bytes.NewReader(FOOTMARK))
		if err != nil {
			return "", err
		}
		icon = imaging.Overlay(icon, mark, image.Pt(0, 0), 1.0)
	}

	circle := applyCircleMask(icon)
	imgBase64, err := getWebpBase64(circle)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(map[string]any{
		"content": imgBase64,
	})
	if err != nil {
		return "", err
	}

	trace := common.UniqueId(asset.AssetID, "footmark-webp-icon")
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, trace, *node.safeUser())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://kernel.mixin.dev/objects/%s/content", hash.String()), nil
}
