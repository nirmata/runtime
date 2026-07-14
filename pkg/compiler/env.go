package compiler

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/kyverno/sdk/extensions/cel/libs/http"
	"github.com/kyverno/sdk/extensions/cel/libs/resource"
	"k8s.io/apiserver/pkg/cel/library"
	"k8s.io/client-go/dynamic"
)

func newBaseEnv() (*cel.Env, error) {
	// create new cel env
	return cel.NewEnv(
		// configure env
		cel.HomogeneousAggregateLiterals(),
		cel.EagerlyValidateDeclarations(true),
		cel.DefaultUTCTimeZone(true),
		cel.CrossTypeNumericComparisons(true),
		// register common libs
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Encoders(),
		ext.Lists(),
		ext.Math(),
		ext.Protos(),
		ext.Sets(),
		ext.Strings(),
		// register kubernetes libs
		library.CIDR(),
		library.Format(),
		library.IP(),
		library.Lists(),
		library.Regex(),
		library.URLs(),
		library.Quantity(),
		library.SemverLib(),
	)
}

func newEnv(client dynamic.Interface) (*cel.Env, error) {
	base, err := newBaseEnv()
	if err != nil {
		return nil, err
	}

	return base.Extend(
		http.Lib(http.Context{ContextInterface: http.NewHTTP()}, http.Latest()),
		resource.Lib(resource.Context{ContextInterface: newResourceProvider(client)}, "", resource.Latest()),
	)
}
