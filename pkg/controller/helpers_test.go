package controller

import (
	"sync"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	corev1 "k8s.io/api/core/v1"
)

// fakeCompiler is a stand in for compiler.Compiler that records the policies it
// was asked to compile and returns a canned result.
type fakeCompiler struct {
	mu       sync.Mutex
	compiled *compiler.CompiledRuntimePolicy
	err      error
	calls    []v1alpha1.RuntimePolicy
}

func (f *fakeCompiler) Compile(rp v1alpha1.RuntimePolicy) (*compiler.CompiledRuntimePolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rp)
	if f.err != nil {
		return nil, f.err
	}
	return f.compiled, nil
}

func (f *fakeCompiler) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type rpCall struct {
	res     *compiler.EvaluationResult
	evType  string
	handler string
}

type podCall struct {
	pod     corev1.Pod
	cgInfos []*containers.ContainerCgroupInfo
	evType  string
}

// recordingHandler records every event it receives. Handlers are invoked from
// goroutines so every field is mutex guarded.
type recordingHandler struct {
	name   string
	rpErr  error
	podErr error

	mu       sync.Mutex
	rpCalls  []rpCall
	podCalls []podCall
}

var _ events.EventIface = (*recordingHandler)(nil)

func (h *recordingHandler) RuntimePolicyEvent(rp *compiler.EvaluationResult, rpEventType string) error {
	h.mu.Lock()
	h.rpCalls = append(h.rpCalls, rpCall{res: rp, evType: rpEventType, handler: h.name})
	h.mu.Unlock()
	return h.rpErr
}

func (h *recordingHandler) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	h.mu.Lock()
	h.podCalls = append(h.podCalls, podCall{pod: pod, cgInfos: cgInfos, evType: podEventType})
	h.mu.Unlock()
	return h.podErr
}

func (h *recordingHandler) runtimePolicyCalls() []rpCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]rpCall(nil), h.rpCalls...)
}

func (h *recordingHandler) podEventCalls() []podCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]podCall(nil), h.podCalls...)
}

func handlers(hs ...*recordingHandler) []events.EventIface {
	out := make([]events.EventIface, 0, len(hs))
	for _, h := range hs {
		out = append(out, h)
	}
	return out
}
