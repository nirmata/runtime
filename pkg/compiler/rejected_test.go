package compiler

import (
	"strings"
	"testing"
)

func TestRejectedTargetNamesValueAndReason(t *testing.T) {
	got := RejectedTarget{Value: "/bin/sh", Reason: ErrPathValueTooLong.Error()}.String()
	if !strings.Contains(got, "/bin/sh") || !strings.Contains(got, ErrPathValueTooLong.Error()) {
		t.Errorf("String() = %q, want it to name both the value and the reason", got)
	}
}
