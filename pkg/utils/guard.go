package utils

import (
	"errors"
	"fmt"
	"runtime/debug"
)

// ErrPanic wraps every error produced by a recovered panic, so callers can
// classify them with errors.Is.
var ErrPanic = errors.New("recovered from panic")

// Guard runs fn and converts a panic into an error, preserving the panic stack.
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
