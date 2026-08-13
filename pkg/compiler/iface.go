package compiler

import "github.com/nirmata/runtime/api/v1alpha1"

type Compiler interface {
	Compile(rp v1alpha1.RuntimePolicy) (*CompiledRuntimePolicy, error)
}
