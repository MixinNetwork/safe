package protocol

import (
	"fmt"

	"github.com/MixinNetwork/multi-party-sig/pkg/party"
)

// Error is a custom error for protocols which contains information about the responsible round in which it occurred,
// and the party responsible.
type Error struct {
	// Culprits is empty if the identity of the misbehaving party cannot be known.
	Culprits []party.ID
	// Err is the underlying error.
	Err error
}

// Error implements error.
func (e Error) Error() string {
	if e.Culprits == nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("culprits: %v: %s", e.Culprits, e.Err)
}

// Unwrap returns the underlying error.
func (e Error) Unwrap() error {
	return e.Err
}
