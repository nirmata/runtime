package utils

import (
	"errors"
	"fmt"
	"runtime/debug"
)

// ErrPanic wraps every error produced by a recovered panic, so callers can
// classify them (`errors.Is(err, utils.ErrPanic)`) for metrics and logging.
var ErrPanic = errors.New("recovered from panic")

// Guard runs fn and converts any panic into an error. Use around every
// boundary that evaluates user-authored input (CEL compile/eval, event
// handler fan-out).
//
// op names the operation being guarded and is prefixed to the returned error.
// A panic value that is itself an error is wrapped so `errors.Is`/`errors.As`
// still reach it. The stack trace is captured in the error message because the
// panic site is otherwise lost by the time the error reaches its handler.
func Guard(op string, fn func() error) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		stack := debug.Stack()
		if perr, ok := r.(error); ok {
			err = fmt.Errorf("%s: %w: %w\n%s", op, ErrPanic, perr, stack)
			return
		}
		err = fmt.Errorf("%s: %w: %v\n%s", op, ErrPanic, r, stack)
	}()
	if fn == nil {
		return fmt.Errorf("%s: nil function", op)
	}
	return fn()
}
