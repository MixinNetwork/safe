package computer

import (
	"context"
	"testing"

	"github.com/MixinNetwork/safe/common"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/stretchr/testify/require"
)

func TestRequest(t *testing.T) {
	require := require.New(t)
	var client *mixin.Client
	ctx := context.Background()
	ctx = common.EnableTestEnvironment(ctx)

}
