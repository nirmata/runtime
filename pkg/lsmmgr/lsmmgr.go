package lsmmgr

import "github.com/nirmata/kyverno-runtime/pkg/compiler"

type LsmManager struct {
	// we
}

func NewLsmManager() *LsmManager {
	return &LsmManager{}
}

func (l *LsmManager) RuntimeBehaviorEvent(compiledRb *compiler.EvaluationResult, eventType string) error
