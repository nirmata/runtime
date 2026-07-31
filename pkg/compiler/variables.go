package compiler

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// TODO: this code also exists in authz. need to centralize it

var (
	VariablesType     = types.NewObjectType("nirmata.variables")
	variablesTypeType = types.NewTypeTypeWithParam(VariablesType)
)

type variablesProvider struct {
	inner  types.Provider
	fields map[string]*types.Type
	names  []string
}

func newVariablesProvider(inner types.Provider) *variablesProvider {
	return &variablesProvider{
		inner:  inner,
		fields: make(map[string]*types.Type),
	}
}

// store the inner variables name and the types they resolve to. this
// function is not part of an interface that cel requires, its a custom function.
func (p *variablesProvider) registerField(name string, t *types.Type) {
	p.fields[name] = t
	p.names = append(p.names, name)
}

func (p *variablesProvider) EnumValue(enumName string) ref.Val {
	return p.inner.EnumValue(enumName)
}

func (p *variablesProvider) FindIdent(identName string) (ref.Val, bool) {
	return p.inner.FindIdent(identName)
}

func (p *variablesProvider) FindStructType(structType string) (*types.Type, bool) {
	if structType == VariablesType.DeclaredTypeName() {
		return variablesTypeType, true
	}
	return p.inner.FindStructType(structType)
}

func (p *variablesProvider) FindStructFieldNames(structType string) ([]string, bool) {
	if structType == VariablesType.DeclaredTypeName() {
		return p.names, true
	}
	return p.inner.FindStructFieldNames(structType)
}

func (p *variablesProvider) FindStructFieldType(structType, fieldName string) (*types.FieldType, bool) {
	if structType == VariablesType.DeclaredTypeName() {
		if t, ok := p.fields[fieldName]; ok {
			return &types.FieldType{
				Type: t,
			}, true
		}
		return nil, false
	}
	return p.inner.FindStructFieldType(structType, fieldName)
}

func (p *variablesProvider) NewValue(structType string, fields map[string]ref.Val) ref.Val {
	return p.inner.NewValue(structType, fields)
}
