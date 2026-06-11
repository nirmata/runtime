package compiler

import "github.com/nirmata/kyverno-runtime/api/v1alpha1"

type Compiler interface {
	Compile(rb v1alpha1.RuntimeBehavior) (*CompiledRuntimeBehavior, error)
}
