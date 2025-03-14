package computer

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net/http"

	"github.com/MixinNetwork/bot-api-go-client/v3"
	"github.com/MixinNetwork/safe/common"
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

func applyCircleMask(img image.Image) ([]byte, error) {
	bounds := img.Bounds()
	dst := image.NewRGBA(bounds)
	draw.Draw(dst, bounds, img, bounds.Min, draw.Src)

	r := float64(size / 2)
	dc := gg.NewContext(size, size)
	dc.DrawCircle(r, r, r)
	dc.Clip()

	mask := image.NewRGBA(bounds)
	dc.SetColor(color.White)
	dc.Clear()
	draw.DrawMask(
		dst,
		bounds,
		dst,
		bounds.Min,
		mask,
		bounds.Min,
		draw.Over,
	)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// https://kernel.mixin.dev/objects/b9dc9ef4e569e047e64cfb229bbd82ff0b597a470477e5731e429d41407e8944
func (node *Node) processAssetIcon(ctx context.Context, asset *bot.AssetNetwork) (string, error) {
	icon, err := readImageFromUrl(asset.IconURL)
	if err != nil {
		return "", err
	}
	mark, _, err := image.Decode(bytes.NewReader(FOOTMARK))
	if err != nil {
		return "", err
	}

	combined := imaging.Overlay(icon, mark, image.Pt(0, 0), 1.0)
	data, err := applyCircleMask(combined)
	if err != nil {
		return "", err
	}

	trace := common.UniqueId(asset.AssetID, "footmark-icon")
	hash, err := common.WriteStorageUntilSufficient(ctx, node.mixin, data, trace, *node.safeUser())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://kernel.mixin.dev/objects/%s", hash.String()), nil
}
