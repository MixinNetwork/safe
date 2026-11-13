package messenger

import "context"

type Messenger interface {
	// ReceiveMessage returns ctx.Err() on cancellation, or ErrorDone when the
	// receive stream ends.
	ReceiveMessage(context.Context) (*MixinMessage, error)
	SendMessage(ctx context.Context, receiver string, b []byte) error
	// QueueMessage returns ctx.Err() if cancellation prevents enqueueing.
	QueueMessage(ctx context.Context, receiver string, b []byte) error
	BroadcastMessage(ctx context.Context, b []byte) error
}
