package apps

import "github.com/MixinNetwork/mixin/common"

func WriteBytes(enc *common.Encoder, b []byte) {
	enc.WriteInt(len(b))
	enc.Write(b)
}
