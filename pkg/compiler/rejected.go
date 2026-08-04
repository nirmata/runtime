package compiler

import "fmt"

// RejectedTarget is a policy value that could not be turned into a kernel map
// entry, together with the reason. Rejections are returned as typed values
// (never dropped, never folded into an error) so callers can log them and
// attach them to policy status.
type RejectedTarget struct {
	Value  string
	Reason string
}

func (r RejectedTarget) String() string {
	return fmt.Sprintf("%q: %s", r.Value, r.Reason)
}
