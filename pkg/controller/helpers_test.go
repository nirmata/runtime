package controller

import (
	"sync"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func (f *fakeCompiler) compiledPolicies() []v1alpha1.RuntimePolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]v1alpha1.RuntimePolicy(nil), f.calls...)
}

// recordedCondition is one RecordCondition call, with the name the caller
// supplied alongside it.
type recordedCondition struct {
	uid  string
	name string
	cond metav1.Condition
}

type fakeStatusRecorder struct {
	mu       sync.Mutex
	recorded []recordedCondition
}

var _ runtimeevent.PolicyStatusRecorder = (*fakeStatusRecorder)(nil)

func (f *fakeStatusRecorder) RecordCondition(policyUID, policyName string, cond metav1.Condition) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, recordedCondition{uid: policyUID, name: policyName, cond: cond})
}

func (f *fakeStatusRecorder) all() []recordedCondition {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCondition(nil), f.recorded...)
}

type rpCall struct {
	res     *compiler.EvaluationResult
	evType  string
	handler string
}

type podCall struct {
	pod      corev1.Pod
	nsLabels map[string]string
	cgInfos  []*containers.ContainerCgroupInfo
	evType   string
}

// recordingRpHandler records every policy event it receives. Handlers are
// invoked from goroutines so every field is mutex guarded. rpPanic makes the
// handler panic, which is what the utils.Guard wrapping in the fan-out has to
// absorb.
type recordingRpHandler struct {
	name    string
	rpErr   error
	rpPanic any

	mu      sync.Mutex
	rpCalls []rpCall
}

var _ events.RuntimePolicyEventHandler = (*recordingRpHandler)(nil)

func (h *recordingRpHandler) RuntimePolicyEvent(rp *compiler.EvaluationResult, rpEventType string) error {
	h.mu.Lock()
	h.rpCalls = append(h.rpCalls, rpCall{res: rp, evType: rpEventType, handler: h.name})
	h.mu.Unlock()
	if h.rpPanic != nil {
		panic(h.rpPanic)
	}
	return h.rpErr
}

func (h *recordingRpHandler) runtimePolicyCalls() []rpCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]rpCall(nil), h.rpCalls...)
}

// recordingPodHandler records every pod event and delete it receives. podErr
// and podPanic apply to both PodEvent and PodDeleted so requeue behavior can
// be driven on either path.
type recordingPodHandler struct {
	name     string
	podErr   error
	podPanic any

	mu           sync.Mutex
	podCalls     []podCall
	deletedCalls []string
}

var _ events.PodEventHandler = (*recordingPodHandler)(nil)

func (h *recordingPodHandler) PodEvent(pod corev1.Pod, nsLabels map[string]string, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	h.mu.Lock()
	h.podCalls = append(h.podCalls, podCall{pod: pod, nsLabels: nsLabels, cgInfos: cgInfos, evType: podEventType})
	h.mu.Unlock()
	if h.podPanic != nil {
		panic(h.podPanic)
	}
	return h.podErr
}

func (h *recordingPodHandler) PodDeleted(uid string) error {
	h.mu.Lock()
	h.deletedCalls = append(h.deletedCalls, uid)
	h.mu.Unlock()
	if h.podPanic != nil {
		panic(h.podPanic)
	}
	return h.podErr
}

func (h *recordingPodHandler) podEventCalls() []podCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]podCall(nil), h.podCalls...)
}

func (h *recordingPodHandler) podDeletedCalls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.deletedCalls...)
}

func rpHandlers(hs ...*recordingRpHandler) []events.RuntimePolicyEventHandler {
	out := make([]events.RuntimePolicyEventHandler, 0, len(hs))
	for _, h := range hs {
		out = append(out, h)
	}
	return out
}

func podHandlers(hs ...*recordingPodHandler) []events.PodEventHandler {
	out := make([]events.PodEventHandler, 0, len(hs))
	for _, h := range hs {
		out = append(out, h)
	}
	return out
}
