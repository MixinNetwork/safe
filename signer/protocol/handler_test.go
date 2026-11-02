package protocol

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProtocolDiagnosticsDuringRoundTransitions(t *testing.T) {
	a, b := securityTestProtocolHandlers(t)
	handlers := []*MultiHandler{a, b}
	done := make(chan struct{})
	var readers sync.WaitGroup
	for _, h := range handlers {
		readers.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
					h.CanAccept(nil)
					_ = h.String()
				}
			}
		})
	}
	defer func() { close(done); readers.Wait() }()
	for range 20 {
		var outgoing []*Message
		for _, h := range handlers {
			outgoing = append(outgoing, securityTestDrainProtocolMessages(h)...)
		}
		if len(outgoing) == 0 {
			break
		}
		for _, message := range outgoing {
			for _, h := range handlers {
				if h.CanAccept(message) {
					h.Accept(message)
				}
			}
		}
	}
	for _, h := range handlers {
		result, err := h.Result()
		require.NoError(t, err)
		require.NotNil(t, result)
	}
}
