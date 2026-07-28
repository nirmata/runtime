// Package monitor turns observed runtime events into findings for
// monitor-mode policies (#42, #17 userspace half).
//
// Monitor mode is the "trial run" of a RuntimePolicy: the kernel programs
// nothing to block, the managers only count what happened, and this package
// decides — in userspace, from the same allow/deny values the enforcing form of
// the policy would program — whether an observation WOULD have been denied. Each
// such observation becomes a reporter.Finding with result "fail" and a
// violation recorded against the policy's status.
//
// Two properties matter more than features here:
//
//   - HandleEvent is on the event hot path. Policy values are compiled into
//     matchers once, when the policy is tracked, so the per-event cost is a
//     selector match plus map lookups.
//   - HandleEvent never panics outward (runtimeevent.Sink contract) and
//     never mutates the event's pod labels: that map is owned by
//     pkg/attribution's index and shared with every other sink.
package monitor

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/containers"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/metrics"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Behavior names emitted on findings; they match reporter.Finding.Behavior.
const (
	BehaviorNetwork = "network"
	BehaviorOpen    = "open"
	BehaviorExec    = "exec"
)

// sinkName is the runtimeevent.Sink name, also used as the metric source label.
const sinkName = "monitor"

// FindingSink receives the findings monitor mode produces. *reporter.Reporter
// satisfies it; tests use a recording fake.
type FindingSink interface {
	Report(reporter.Finding)
}

// trackedPolicy is a monitor-mode policy in its per-event-ready form.
//
// Every field is immutable after construction: RuntimePolicyEvent replaces the
// whole value rather than mutating it, so HandleEvent can read one outside the
// lock. This also isolates monitor from egressmgr, which mutates the
// EvaluationResult it was handed in place (#53) — the pairs are copied here.
type trackedPolicy struct {
	uid      string
	name     string
	selector labels.Selector
	net      netBehavior
	open     pathBehavior
	exec     pathBehavior
}

// Monitor implements events.EventIface (policy tracking) and
// runtimeevent.Sink (event evaluation).
type Monitor struct {
	log     logr.Logger
	sink    FindingSink
	status  runtimeevent.PolicyStatusRecorder
	metrics *metrics.Metrics

	mu sync.RWMutex
	// policies is keyed by policy uid. Only monitor-mode policies with at
	// least one behavior entry are present.
	policies map[string]*trackedPolicy
}

var (
	_ events.EventIface = (*Monitor)(nil)
	_ runtimeevent.Sink = (*Monitor)(nil)
	_ FindingSink       = (*reporter.Reporter)(nil)
)

// New builds a Monitor. sink, status and m may each be nil: a daemon without a
// reporter (or without status writing, or without metrics) still evaluates
// events, it just has fewer places to put the result.
func New(log logr.Logger, findings FindingSink, status runtimeevent.PolicyStatusRecorder, m *metrics.Metrics) *Monitor {
	return &Monitor{
		log:      log.WithName(sinkName),
		sink:     findings,
		status:   status,
		metrics:  m,
		policies: make(map[string]*trackedPolicy),
	}
}

// Name identifies this sink to the collector.
func (m *Monitor) Name() string { return sinkName }

// PodEvent is a no-op: events carry their own attributed pod identity (filled
// by pkg/attribution), so monitor keeps no pod state at all.
func (m *Monitor) PodEvent(pod corev1.Pod, cgInfos []*containers.ContainerCgroupInfo, podEventType string) error {
	return nil
}

// RuntimePolicyEvent tracks monitor-mode policies and forgets everything else.
//
// A policy that leaves monitor mode (to enforce, to discover, or by being
// deleted) is untracked, as is one whose behaviors no longer hold any value:
// neither can ever produce a finding, and keeping it would only slow the event
// path down.
func (m *Monitor) RuntimePolicyEvent(rp *compiler.EvaluationResult, rpEventType string) error {
	if rp == nil {
		return fmt.Errorf("monitor: nil evaluation result for %s event", rpEventType)
	}

	if rpEventType == events.EventTypeDelete {
		m.untrack(rp.UID, "deleted")
		return nil
	}

	if rp.Mode != compiler.ModeMonitor {
		// discover mode observes for the inventory (PR B) and emits no
		// findings; enforce mode blocks in the kernel and needs no userspace
		// decision.
		m.untrack(rp.UID, "mode is not monitor")
		return nil
	}

	tp := &trackedPolicy{
		uid:      rp.UID,
		name:     rp.Name,
		selector: rp.Selector,
		net:      compileNetBehavior(rp.IPs),
		open:     compilePathBehavior(rp.Open),
		exec:     compilePathBehavior(rp.Exec),
	}
	if !tp.net.present && !tp.open.present && !tp.exec.present {
		m.untrack(rp.UID, "policy has no network, open or exec entries")
		return nil
	}
	if tp.selector == nil {
		// A nil selector matches nothing here rather than everything: a
		// selector that failed to build must never widen a policy's scope.
		m.untrack(rp.UID, "policy has no usable pod selector")
		return nil
	}

	m.mu.Lock()
	m.policies[tp.uid] = tp
	m.mu.Unlock()

	m.log.V(2).Info("tracking monitor-mode policy", "policy", tp.name, "uid", tp.uid,
		"network", tp.net.present, "open", tp.open.present, "exec", tp.exec.present)
	return nil
}

func (m *Monitor) untrack(uid, reason string) {
	m.mu.Lock()
	_, tracked := m.policies[uid]
	delete(m.policies, uid)
	m.mu.Unlock()
	if tracked {
		m.log.V(2).Info("no longer monitoring policy", "uid", uid, "reason", reason)
	}
}

// tracked returns a snapshot of the tracked policies. The values are immutable,
// so the caller may read them after the lock is released.
func (m *Monitor) tracked() []*trackedPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.policies) == 0 {
		return nil
	}
	out := make([]*trackedPolicy, 0, len(m.policies))
	for _, tp := range m.policies {
		out = append(out, tp)
	}
	return out
}

// Len reports how many monitor-mode policies are tracked (test/debug helper).
func (m *Monitor) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.policies)
}

// HandleEvent evaluates ev against every tracked monitor-mode policy that
// selects the event's pod, emitting at most one finding — and exactly one
// recorded violation — per (policy, pod) for this event.
//
// It satisfies runtimeevent.Sink: fast, non-blocking and never panicking
// outward. The whole body runs behind utils.Guard because the finding sink and
// the status recorder are interfaces supplied by the daemon.
func (m *Monitor) HandleEvent(ev runtimeevent.Event) {
	if err := utils.Guard("monitor: handling event", func() error {
		m.handleEvent(ev)
		return nil
	}); err != nil {
		m.log.Error(err, "handling event failed", "kind", string(ev.Kind), "podUid", ev.Pod.UID)
	}
}

func (m *Monitor) handleEvent(ev runtimeevent.Event) {
	behavior, target := targetOf(ev)
	if behavior == "" {
		// not a kind monitor mode can decide on (dns/tls/http are inputs to
		// the AI engine in PR B, not to allow/deny lists)
		return
	}

	policies := m.tracked()
	if len(policies) == 0 {
		return
	}

	for _, tp := range policies {
		if !tp.selector.Matches(labels.Set(ev.Pod.Labels)) {
			continue
		}
		d := tp.eval(behavior, ev)
		if !d.violation {
			continue
		}
		// Denied carries "would have been blocked" in monitor mode. The sink
		// contract passes the event by value, so this is the copy the finding
		// is built from; nothing upstream is mutated.
		ev.Denied = true
		m.record(tp, behavior, target, d, ev)
	}
}

// eval dispatches to the behavior matching the event's kind.
func (tp *trackedPolicy) eval(behavior string, ev runtimeevent.Event) decision {
	switch behavior {
	case BehaviorNetwork:
		return tp.net.eval(ev.Net.DestIP)
	case BehaviorOpen:
		return tp.open.eval(ev.Open.Path)
	case BehaviorExec:
		return tp.exec.eval(ev.Exec.Filename)
	}
	return decision{}
}

// record emits the finding and the status violation for one (policy, pod).
func (m *Monitor) record(tp *trackedPolicy, behavior, target string, d decision, ev runtimeevent.Event) {
	// The violation happened whether or not it can be reported, so status is
	// recorded first and unconditionally.
	if m.status != nil {
		if err := utils.Guard("monitor: recording violation", func() error {
			m.status.RecordViolation(tp.uid, ev.Pod.UID)
			return nil
		}); err != nil {
			m.log.Error(err, "recording violation failed", "policy", tp.name, "uid", tp.uid)
		}
	}

	m.log.V(4).Info("monitor-mode violation", "policy", tp.name, "uid", tp.uid,
		"behavior", behavior, "podUid", ev.Pod.UID, "count", ev.Count, "denied", ev.Denied)

	if m.sink == nil {
		return
	}
	// A finding without a usable namespace cannot address a namespaced Report
	// and would be dropped by the reporter; count it here so the gap is
	// visible instead of silent.
	if errs := validation.IsDNS1123Label(ev.Pod.Namespace); len(errs) > 0 {
		if m.metrics != nil {
			m.metrics.EventsDropped.WithLabelValues(sinkName, "unattributed").Inc()
		}
		m.log.V(4).Info("dropping finding for unattributed event",
			"policy", tp.name, "uid", tp.uid, "behavior", behavior)
		return
	}

	f := reporter.Finding{
		PolicyName: tp.name,
		PolicyUID:  tp.uid,
		Behavior:   behavior,
		Severity:   reporter.DefaultSeverity,
		Result:     reporter.ResultFail,
		Message:    message(tp.name, behavior, target, d, ev.Count),
		Pod:        ev.Pod,
		Timestamp:  ev.Time,
	}
	switch behavior {
	case BehaviorNetwork:
		f.Net = &reporter.NetSummary{
			DestIP:   ev.Net.DestIP.String(),
			DestPort: ev.Net.DestPort,
		}
	case BehaviorOpen:
		f.Process = &reporter.ProcessSummary{Comm: ev.Comm}
	case BehaviorExec:
		f.Process = &reporter.ProcessSummary{
			Comm: ev.Comm,
			Argv: strings.Join(ev.Exec.Argv, " "),
		}
	}

	if err := utils.Guard("monitor: reporting finding", func() error {
		m.sink.Report(f)
		return nil
	}); err != nil {
		m.log.Error(err, "reporting finding failed", "policy", tp.name, "uid", tp.uid)
	}
}

// targetOf maps an event to the behavior it is decided against and the target
// value named in the finding message. It returns "" for kinds monitor mode has
// no allow/deny list for, and for events whose facts pointer is missing.
func targetOf(ev runtimeevent.Event) (behavior, target string) {
	switch ev.Kind {
	case runtimeevent.KindNet:
		if ev.Net == nil || !ev.Net.DestIP.IsValid() {
			return "", ""
		}
		return BehaviorNetwork, destination(ev.Net.DestIP, ev.Net.DestPort)
	case runtimeevent.KindOpen:
		if ev.Open == nil || ev.Open.Path == "" {
			return "", ""
		}
		return BehaviorOpen, ev.Open.Path
	case runtimeevent.KindExec:
		if ev.Exec == nil || ev.Exec.Filename == "" {
			return "", ""
		}
		return BehaviorExec, ev.Exec.Filename
	}
	return "", ""
}

func destination(addr netip.Addr, port uint16) string {
	if port == 0 {
		return addr.String()
	}
	return netip.AddrPortFrom(addr, port).String()
}

// message renders the finding message. It names only the policy and the target
// the policy itself listed — never event payload — so it is safe by
// construction (reporter.sanitize is the backstop).
func message(policy, behavior, target string, d decision, count uint32) string {
	var b strings.Builder
	b.WriteString("monitor mode: ")
	switch behavior {
	case BehaviorNetwork:
		b.WriteString("egress to ")
	case BehaviorOpen:
		b.WriteString("open of ")
	case BehaviorExec:
		b.WriteString("exec of ")
	}
	b.WriteString(target)
	if count > 1 {
		fmt.Fprintf(&b, " (%d occurrences)", count)
	}
	b.WriteString(" would have been denied by policy ")
	b.WriteString(policy)
	if d.defaultDeny {
		b.WriteString(" (default deny)")
	}
	return b.String()
}
