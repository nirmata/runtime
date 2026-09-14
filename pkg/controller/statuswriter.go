package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nirmata/runtime/api/v1alpha1"
	v1alpha1client "github.com/nirmata/runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/runtime/pkg/compiler"
	"github.com/nirmata/runtime/pkg/events"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// DefaultStatusFlushInterval is the flush cadence used by the daemon.
const DefaultStatusFlushInterval = 30 * time.Second

const (
	execTraceSource       = "exec-trace"
	dnsQuerySource        = "dnsquery"
	openExecObserveSource = "openexec-observe"
	egressObserveSource   = "egress-observe"
)

// ExpectedSourceNodes describes the DaemonSet nodes that should publish event
// source status. A non-synced or incomplete inventory cannot prove a source is
// available everywhere.
type ExpectedSourceNodes struct {
	Names   []string
	Desired int
	Synced  bool
}

type sourceStatus struct {
	state  runtimeevent.SourceState
	reason string
}

// policyStatusState is this node's view of one policy's status.
type policyStatusState struct {
	// name is needed to address the object. An entry whose name is still unknown
	// waits, unflushed, until a caller supplies one.
	name string
	mode string

	// conditions is keyed by condition type; the last write wins.
	conditions map[string]metav1.Condition
	// gen increments on every mutation. A flush records the gen it observed
	// and only clears dirty when nothing changed while the API call was in
	// flight.
	gen   uint64
	dirty bool
}

func newPolicyStatusState() *policyStatusState {
	return &policyStatusState{
		conditions: make(map[string]metav1.Condition),
	}
}

func (p *policyStatusState) touch() {
	p.gen++
	p.dirty = true
}

// StatusWriter turns the RuntimePolicy event stream into this node's shard of
// each policy's status. Every daemon in the DaemonSet writes the same
// cluster-scoped object, so a node only ever replaces its own entry in
// status.nodes.
type StatusWriter struct {
	client   v1alpha1client.Interface
	nodeName string
	interval time.Duration
	log      logr.Logger
	// clock is injectable for tests.
	clock func() time.Time
	// nodeGone answers only when it can be authoritative: true means the
	// named node no longer exists, false means it exists or the caller
	// cannot yet tell. A nil func disables shard pruning.
	nodeGone func(name string) bool
	// onConditionChanged fires once a flush actually persists a condition
	// whose status, reason, or message changed. It runs from the flush path,
	// against what was written to the API, not from RecordCondition: see
	// notifyConditionChanges. A nil func disables it.
	onConditionChanged func(policyUID, policyName string, cond metav1.Condition)
	// expectedSourceNodes is nil when source status is aggregated over the
	// reporting shards.
	expectedSourceNodes func() ExpectedSourceNodes

	mu sync.Mutex
	// policies is keyed by policy UID.
	policies map[string]*policyStatusState
	// sources is daemon-wide state, retained before a relevant policy appears.
	sources map[string]sourceStatus
}

// NewStatusWriter builds a StatusWriter for this node. A non-positive interval
// falls back to DefaultStatusFlushInterval. A nil onConditionChanged disables
// the change callback.
func NewStatusWriter(client v1alpha1client.Interface, nodeName string, interval time.Duration, log logr.Logger,
	nodeGone func(name string) bool, onConditionChanged func(policyUID, policyName string, cond metav1.Condition)) *StatusWriter {
	if interval <= 0 {
		interval = DefaultStatusFlushInterval
	}
	return &StatusWriter{
		client:             client,
		nodeName:           nodeName,
		interval:           interval,
		log:                log.WithName("statuswriter"),
		clock:              time.Now,
		nodeGone:           nodeGone,
		onConditionChanged: onConditionChanged,
		policies:           make(map[string]*policyStatusState),
		sources:            make(map[string]sourceStatus),
	}
}

// SetExpectedSourceNodes installs the DaemonSet membership view used to
// aggregate event source status. It marks every policy dirty because placement
// changes can alter a cluster condition without a policy event.
func (s *StatusWriter) SetExpectedSourceNodes(f func() ExpectedSourceNodes) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectedSourceNodes = f
	for _, st := range s.policies {
		st.touch()
	}
}

// MarkAllDirty makes the next flush recompute every policy's aggregate status.
func (s *StatusWriter) MarkAllDirty() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.policies {
		st.touch()
	}
}

// RecordSourceStatus records a daemon-wide source lifecycle transition. The
// source state is projected into relevant policy shards during flush.
func (s *StatusWriter) RecordSourceStatus(source string, state runtimeevent.SourceState, reason string) {
	if source == "" || reason == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.sources[source]; ok && previous.state == state && previous.reason == reason {
		return
	}
	s.sources[source] = sourceStatus{state: state, reason: reason}
	if state == runtimeevent.SourceStateUnavailable {
		s.log.V(0).Info("event source is unavailable", "source", source, "reason", reason)
	}
	for _, st := range s.policies {
		st.touch()
	}
}

// getOrCreate returns the state for a policy UID, creating it if a recorder
// call arrived before the policy's own event. Callers hold s.mu.
func (s *StatusWriter) getOrCreate(uid string) *policyStatusState {
	st, ok := s.policies[uid]
	if !ok {
		st = newPolicyStatusState()
		s.policies[uid] = st
	}
	return st
}

// RuntimePolicyEvent caches the policy's identity and mode.
func (s *StatusWriter) RuntimePolicyEvent(res *compiler.EvaluationResult, eventType string) error {
	if res == nil || res.UID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if eventType == events.EventTypeDelete {
		// the object is gone, so there is no status left to write
		delete(s.policies, res.UID)
		return nil
	}

	st := s.getOrCreate(res.UID)
	if res.Name != "" {
		st.name = res.Name
	}
	st.mode = res.Mode
	// an availability condition recorded under the other mode has no writer
	// left to correct it: the managers only record the type matching the
	// current mode, so it would sit stale in the map forever
	switch res.Mode {
	case compiler.ModeEnforce:
		delete(st.conditions, v1alpha1.ConditionObservationAvailable)
	case compiler.ModeMonitor:
		delete(st.conditions, v1alpha1.ConditionEnforcementAvailable)
	}
	st.touch()
	return nil
}

// RecordCondition stores a condition to be merged into the policy's status on
// the next flush. Re-recording an identical condition is a no-op so a manager
// that reports the same condition on every event does not cause API churn.
func (s *StatusWriter) RecordCondition(policyUID, policyName string, cond metav1.Condition) {
	if policyUID == "" || cond.Type == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.getOrCreate(policyUID)
	if policyName != "" {
		st.name = policyName
	}
	if prev, ok := st.conditions[cond.Type]; ok &&
		prev.Status == cond.Status && prev.Reason == cond.Reason && prev.Message == cond.Message {
		return
	}
	// apimeta.SetStatusCondition would fill a zero timestamp from time.Now(),
	// which is a second clock: the conditions this writer builds itself all come
	// from s.clock(), and a test with a fake one would see the two disagree.
	if cond.LastTransitionTime.IsZero() {
		cond.LastTransitionTime = metav1.NewTime(s.clock())
	}
	st.conditions[cond.Type] = cond
	st.touch()
}

// baseAppliedCondition reports what spec.mode alone promises: nothing has yet
// asked whether that promise was kept.
func (s *StatusWriter) baseAppliedCondition(mode string) metav1.Condition {
	status := metav1.ConditionTrue
	reason := v1alpha1.ReasonEnforcing
	message := "the policy is being enforced"
	switch mode {
	case compiler.ModeMonitor:
		reason = v1alpha1.ReasonMonitoring
		message = "the policy is observed and reported but never blocks"
	case "":
		// Spec.Mode's structural default means the API server never serves this;
		// it only guards a spec built without going through API-server defaulting.
		status = metav1.ConditionFalse
		reason = v1alpha1.ReasonNoMode
		message = "the policy sets no spec.mode, so it is neither enforced nor reported"
	}
	return metav1.Condition{
		Type:               v1alpha1.ConditionApplied,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(s.clock()),
	}
}

// appliedCondition derives Applied from the mode plus the availability and
// pods-matched conditions handed to it. A mode that promises enforcement or
// observation, but whose attachment failed or whose selector matches no pod,
// must not read the same as one that is working.
func (s *StatusWriter) appliedCondition(mode string, conditions map[string]metav1.Condition) metav1.Condition {
	cond := s.baseAppliedCondition(mode)

	var gateType string
	switch mode {
	case compiler.ModeEnforce:
		gateType = v1alpha1.ConditionEnforcementAvailable
	case compiler.ModeMonitor:
		gateType = v1alpha1.ConditionObservationAvailable
	default:
		return cond
	}

	// an attachment that never took is checked first: it is the more
	// actionable of the two (fix the node) and would otherwise be masked by
	// a selector that also happens to match nothing.
	if gate, ok := conditions[gateType]; ok && gate.Status == metav1.ConditionFalse {
		cond.Status = metav1.ConditionFalse
		cond.Reason = gate.Reason
		cond.Message = gate.Message
		return cond
	}
	if compiler.IsObserveMode(mode) {
		if gate, ok := conditions[v1alpha1.ConditionEventSourcesAvailable]; ok && gate.Status != metav1.ConditionTrue {
			cond.Status = gate.Status
			cond.Reason = gate.Reason
			cond.Message = gate.Message
			return cond
		}
	}

	if gate, ok := conditions[v1alpha1.ConditionPodsMatched]; ok && gate.Status == metav1.ConditionFalse {
		cond.Status = metav1.ConditionFalse
		cond.Reason = gate.Reason
		cond.Message = gate.Message
	}
	return cond
}

// Run flushes dirty policy statuses every interval, and once more when ctx is
// cancelled so the last observation is not lost on shutdown.
func (s *StatusWriter) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// the passed context is already cancelled, so the final write
			// needs one that is not
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if err := s.Flush(final); err != nil {
				s.log.Error(err, "final status flush failed")
			}
			return nil
		case <-ticker.C:
			if err := s.Flush(ctx); err != nil {
				s.log.Error(err, "status flush failed")
			}
		}
	}
}

// flushItem is a snapshot of one policy's pending status, taken under the lock
// so the API calls happen without holding it.
type flushItem struct {
	uid        string
	name       string
	mode       string
	conditions []metav1.Condition
	signals    map[string]metav1.Condition
	sources    map[string]sourceStatus
	// explicitApplied marks a directly recorded Applied, which the derived
	// cluster-scoped one must stand aside for.
	explicitApplied bool
	gen             uint64
}

// Flush writes every dirty policy's shard. It is exported so the daemon (and
// tests) can force a write without waiting for the interval.
func (s *StatusWriter) Flush(ctx context.Context) error {
	var errs []error
	for _, item := range s.snapshot() {
		if err := s.flushOne(ctx, item); err != nil {
			errs = append(errs, fmt.Errorf("writing status of RuntimePolicy %s: %w", item.name, err))
			continue
		}
		s.markClean(item)
	}
	return errors.Join(errs...)
}

func (s *StatusWriter) snapshot() []flushItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	items := make([]flushItem, 0, len(s.policies))
	for uid, st := range s.policies {
		if !st.dirty {
			continue
		}
		if st.name == "" {
			// no caller has supplied a name, so the object cannot be
			// addressed yet; stay dirty and retry next tick
			s.log.V(2).Info("policy status pending: no name known yet", "policyUid", uid)
			continue
		}
		item := flushItem{
			uid:     uid,
			name:    st.name,
			mode:    st.mode,
			signals: make(map[string]metav1.Condition, len(st.conditions)),
			sources: make(map[string]sourceStatus, len(s.sources)),
			gen:     st.gen,
		}
		for name, status := range s.sources {
			item.sources[name] = status
		}
		for typ, condition := range st.conditions {
			item.signals[typ] = condition
		}
		conds := make([]metav1.Condition, 0, len(st.conditions))
		for t, c := range st.conditions {
			switch t {
			case v1alpha1.ConditionApplied:
				// reportCompileFailure records Applied directly: nothing
				// compiled, so nothing else bears on whether the policy applied
				item.explicitApplied = true
			case v1alpha1.ConditionEnforcementAvailable,
				v1alpha1.ConditionObservationAvailable,
				v1alpha1.ConditionPodsMatched:
				// these reach the status through this node's shard and the
				// cluster aggregation, never as direct cluster-scoped writes
				continue
			}
			conds = append(conds, c)
		}
		sort.Slice(conds, func(i, j int) bool { return conds[i].Type < conds[j].Type })
		item.conditions = conds
		items = append(items, item)
	}
	return items
}

// markClean clears the dirty flag only if nothing changed while the write was
// in flight.
func (s *StatusWriter) markClean(item flushItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.policies[item.uid]; ok && st.gen == item.gen {
		st.dirty = false
	}
}

// forget drops all local state for a policy that no longer exists.
func (s *StatusWriter) forget(uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, uid)
}

func (s *StatusWriter) flushOne(ctx context.Context, item flushItem) error {
	rpClient := s.client.RuntimeV1alpha1().RuntimePolicies()
	now := metav1.NewTime(s.clock())

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur, err := rpClient.Get(ctx, item.name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				s.log.V(2).Info("RuntimePolicy is gone, dropping its status shard", "policy", item.name)
				s.forget(item.uid)
				return nil
			}
			return err
		}
		if item.uid != "" && string(cur.UID) != "" && string(cur.UID) != item.uid {
			// the name was reused by a different object; this shard is stale
			s.log.V(2).Info("RuntimePolicy UID changed, dropping stale status shard",
				"policy", item.name, "want", item.uid, "got", string(cur.UID))
			s.forget(item.uid)
			return nil
		}

		before := cur.Status
		updated, ok := cur.DeepCopyObject().(*v1alpha1.RuntimePolicy)
		if !ok {
			return fmt.Errorf("deep copy of RuntimePolicy %s returned an unexpected type", item.name)
		}

		s.pruneDeletedNodeShards(&updated.Status)
		dependencies := sourceDependencies(cur.Spec)
		shard := signalShard(item.signals, item.sources, dependencies)
		shard.NodeName = s.nodeName
		shard.LastEvaluatedTime = &now
		setNodeShard(&updated.Status, shard)
		recomputeLastEvaluated(&updated.Status)
		for _, cond := range item.conditions {
			if cond.Reason == "" {
				// Reason is required by the API; a condition without one would
				// be rejected for the whole object
				s.log.V(0).Info("dropping a status condition with no reason",
					"policy", item.name, "condition", cond.Type)
				continue
			}
			apimeta.SetStatusCondition(&updated.Status.Conditions, cond)
		}
		s.setClusterConditions(&updated.Status, currentPolicyMode(cur.Spec, item.mode), item.explicitApplied, dependencies)

		if apiequality.Semantic.DeepEqual(before, updated.Status) {
			// nothing to say; skip the write entirely
			return nil
		}

		if _, err := rpClient.UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
			return err
		}
		s.notifyConditionChanges(item.uid, item.name, before.Conditions, updated.Status.Conditions)
		return nil
	})
}

// notifyConditionChanges fires onConditionChanged for every condition whose
// Status, Reason, or Message differs between before and after: what this node
// actually just persisted, not the raw arguments a caller passed to
// RecordCondition. Applied is usually never passed to RecordCondition at
// all — setClusterConditions derives it here, in this method, from
// EnforcementAvailable/ObservationAvailable/PodsMatched — so a hook on
// RecordCondition itself would miss most real Applied transitions. Comparing
// the object's persisted state also means a process restart, which starts
// this node's in-memory condition cache empty, cannot manufacture a spurious
// notification: before is read fresh from the API on every flush.
func (s *StatusWriter) notifyConditionChanges(policyUID, policyName string, before, after []metav1.Condition) {
	if s.onConditionChanged == nil {
		return
	}
	beforeByType := make(map[string]metav1.Condition, len(before))
	for _, c := range before {
		beforeByType[c.Type] = c
	}
	for _, c := range after {
		if prev, ok := beforeByType[c.Type]; ok &&
			prev.Status == c.Status && prev.Reason == c.Reason && prev.Message == c.Message {
			continue
		}
		s.onConditionChanged(policyUID, policyName, c)
	}
}

// pruneDeletedNodeShards drops the shards left behind by nodes that no longer
// exist, so a deleted node's last-known signals stop feeding the aggregate.
// This node's own shard is never pruned: the flush about to rewrite it is
// proof the node is alive, whatever the watch behind nodeGone currently says.
func (s *StatusWriter) pruneDeletedNodeShards(status *v1alpha1.RuntimePolicyStatus) {
	if s.nodeGone == nil {
		return
	}
	kept := status.Nodes[:0]
	for _, n := range status.Nodes {
		if n.NodeName != s.nodeName && s.nodeGone(n.NodeName) {
			s.log.V(2).Info("dropping the status shard of a deleted node", "node", n.NodeName)
			continue
		}
		kept = append(kept, n)
	}
	status.Nodes = kept
}

// setNodeShard replaces this node's entry in status.nodes, leaving every other
// node's entry untouched. Entries stay sorted by node name so the list does
// not churn between writers.
func setNodeShard(status *v1alpha1.RuntimePolicyStatus, shard v1alpha1.NodePolicyStatus) {
	for i := range status.Nodes {
		if status.Nodes[i].NodeName == shard.NodeName {
			status.Nodes[i] = shard
			return
		}
	}
	// insert in sorted position
	idx := len(status.Nodes)
	for i := range status.Nodes {
		if status.Nodes[i].NodeName > shard.NodeName {
			idx = i
			break
		}
	}
	status.Nodes = append(status.Nodes, v1alpha1.NodePolicyStatus{})
	copy(status.Nodes[idx+1:], status.Nodes[idx:])
	status.Nodes[idx] = shard
}

// recomputeLastEvaluated lifts the newest per-node timestamp to the top level,
// so a node never has to guess what the other nodes contributed.
func recomputeLastEvaluated(status *v1alpha1.RuntimePolicyStatus) {
	var latest *metav1.Time
	for i := range status.Nodes {
		n := &status.Nodes[i]
		if n.LastEvaluatedTime == nil {
			continue
		}
		if latest == nil || n.LastEvaluatedTime.After(latest.Time) {
			t := *n.LastEvaluatedTime
			latest = &t
		}
	}
	if latest != nil {
		status.LastEvaluatedTime = latest
	}
}

// signalShard reduces recorded conditions to the compact per-node fields the
// cluster-scoped aggregation reads.
func signalShard(conditions map[string]metav1.Condition, sources map[string]sourceStatus, dependencies []string) v1alpha1.NodePolicyStatus {
	var shard v1alpha1.NodePolicyStatus
	if c, ok := conditions[v1alpha1.ConditionEnforcementAvailable]; ok {
		shard.EnforcementAvailable = conditionBool(c)
	}
	if c, ok := conditions[v1alpha1.ConditionObservationAvailable]; ok {
		shard.ObservationAvailable = conditionBool(c)
	}
	if c, ok := conditions[v1alpha1.ConditionPodsMatched]; ok {
		shard.PodsMatched = conditionBool(c)
	}
	for _, t := range []string{v1alpha1.ConditionEnforcementAvailable, v1alpha1.ConditionObservationAvailable} {
		if c, ok := conditions[t]; ok && c.Status == metav1.ConditionFalse {
			shard.Message = c.Message
			break
		}
	}
	for _, name := range dependencies {
		shard.EventSources = append(shard.EventSources, eventSourceStatus(name, sources[name]))
	}
	return shard
}

func conditionBool(c metav1.Condition) *bool {
	v := c.Status == metav1.ConditionTrue
	return &v
}

// setClusterConditions derives the cluster-scoped availability, pods-matched
// and Applied conditions from the per-node shards, so every daemon publishes
// the same top-level answer instead of its own node's.
func (s *StatusWriter) setClusterConditions(status *v1alpha1.RuntimePolicyStatus, mode string, explicitApplied bool, sourceDependencies []string) {
	now := metav1.NewTime(s.clock())
	agg := make(map[string]metav1.Condition, 4)
	// a type no shard reports is removed rather than left as written: keeping
	// it would preserve a value the shards no longer back
	record := func(c metav1.Condition, ok bool) {
		if !ok {
			apimeta.RemoveStatusCondition(&status.Conditions, c.Type)
			return
		}
		agg[c.Type] = c
		apimeta.SetStatusCondition(&status.Conditions, c)
	}
	record(aggregateAvailability(status.Nodes, now, v1alpha1.ConditionEnforcementAvailable,
		v1alpha1.ReasonEnforcementAvailable, v1alpha1.ReasonEnforcementUnavailable,
		func(n *v1alpha1.NodePolicyStatus) *bool { return n.EnforcementAvailable }))
	record(aggregateAvailability(status.Nodes, now, v1alpha1.ConditionObservationAvailable,
		v1alpha1.ReasonObservationAvailable, v1alpha1.ReasonObservationUnavailable,
		func(n *v1alpha1.NodePolicyStatus) *bool { return n.ObservationAvailable }))
	record(aggregatePodsMatched(status.Nodes, now))
	expected, hasExpected := s.sourceNodes()
	record(aggregateEventSources(status.Nodes, now, sourceDependencies, expected, hasExpected))
	if !explicitApplied {
		apimeta.SetStatusCondition(&status.Conditions, s.appliedCondition(mode, agg))
	}
}

func currentPolicyMode(spec v1alpha1.RuntimePolicySpec, fallback string) string {
	if spec.Mode != nil {
		return string(*spec.Mode)
	}
	return fallback
}

func sourceDependencies(spec v1alpha1.RuntimePolicySpec) []string {
	if spec.Mode == nil || !compiler.IsObserveMode(string(*spec.Mode)) {
		return nil
	}
	var dependencies []string
	for _, behavior := range spec.Behaviors {
		if declaresTargets(behavior.Open) || declaresTargets(behavior.Exec) {
			dependencies = append(dependencies, openExecObserveSource)
		}
		if declaresTargets(behavior.Network) || declaresTargets(behavior.Protocol) {
			dependencies = append(dependencies, egressObserveSource)
		}
		if declaresTargets(behavior.Exec) {
			dependencies = append(dependencies, execTraceSource)
		}
		if declaresTargets(behavior.DNS) {
			dependencies = append(dependencies, dnsQuerySource)
		}
	}
	sort.Strings(dependencies)
	return slices.Compact(dependencies)
}

func declaresTargets(behavior *v1alpha1.Behavior) bool {
	if behavior == nil {
		return false
	}
	// Expressions can become nonempty on re-evaluation without a spec update.
	for _, rule := range []*v1alpha1.BehaviorRule{behavior.Allow, behavior.Deny} {
		if rule != nil && (len(rule.Values) != 0 || rule.Expression != "") {
			return true
		}
	}
	return false
}

func eventSourceStatus(name string, status sourceStatus) v1alpha1.EventSourceStatus {
	result := v1alpha1.EventSourceStatus{Name: name, Status: metav1.ConditionUnknown, Reason: status.reason, Message: sourceMessage(name, status)}
	if result.Reason == "" {
		result.Reason = runtimeevent.SourceReasonStarting
	}
	switch status.state {
	case runtimeevent.SourceStateAvailable:
		result.Status = metav1.ConditionTrue
	case runtimeevent.SourceStateUnavailable:
		result.Status = metav1.ConditionFalse
	}
	return result
}

func sourceMessage(name string, status sourceStatus) string {
	switch name {
	case execTraceSource:
		if status.state == runtimeevent.SourceStateAvailable {
			return "exec trace source is available"
		}
		if status.state == runtimeevent.SourceStateUnavailable {
			if status.reason == runtimeevent.SourceReasonDependencyUnavailable {
				return "exec trace source is unavailable because the open/exec manager could not load; argv and exec filename observations are unavailable"
			}
			return "exec trace source is unavailable; argv observations are unavailable, but exec filename observations may remain available"
		}
		return "exec trace source is starting"
	case dnsQuerySource:
		if status.state == runtimeevent.SourceStateAvailable {
			return "DNS query source is available"
		}
		if status.state == runtimeevent.SourceStateUnavailable {
			return "DNS query source is unavailable; DNS name observations are unavailable"
		}
		return "DNS query source is starting"
	case openExecObserveSource:
		if status.state == runtimeevent.SourceStateAvailable {
			return "open/exec observation counter source is available"
		}
		if status.state == runtimeevent.SourceStateUnavailable {
			return "open/exec observation counter source is unavailable; file-open observations and exec filename counter observations are unavailable"
		}
		return "open/exec observation counter source is starting"
	case egressObserveSource:
		if status.state == runtimeevent.SourceStateAvailable {
			return "egress observation counter source is available"
		}
		if status.state == runtimeevent.SourceStateUnavailable {
			return "egress observation counter source is unavailable; network and protocol observations are unavailable"
		}
		return "egress observation counter source is starting"
	default:
		return "event source status is unavailable"
	}
}

func aggregateEventSources(nodes []v1alpha1.NodePolicyStatus, now metav1.Time, dependencies []string, expected ExpectedSourceNodes, hasExpected bool) (metav1.Condition, bool) {
	cond := metav1.Condition{Type: v1alpha1.ConditionEventSourcesAvailable, LastTransitionTime: now}
	if len(dependencies) == 0 {
		return cond, false
	}
	if !hasExpected {
		for _, node := range nodes {
			if len(node.EventSources) != 0 {
				return aggregateEventSourceNodes(nodes, now, dependencies, len(nodes), false)
			}
		}
		return cond, false
	}
	expectedNames := make(map[string]struct{}, len(expected.Names))
	for _, name := range expected.Names {
		if name != "" {
			expectedNames[name] = struct{}{}
		}
	}
	if expected.Desired == 0 && expected.Synced {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionUnknown, v1alpha1.ReasonEventSourcesUnknown, "event source status is unknown because there are no expected daemon nodes"
		return cond, true
	}
	incomplete := !expected.Synced || len(expectedNames) != expected.Desired
	if incomplete {
		return aggregateEventSourceNodes(nodes, now, dependencies, expected.Desired, true)
	}
	byName := make(map[string]v1alpha1.NodePolicyStatus, len(nodes))
	for _, node := range nodes {
		byName[node.NodeName] = node
	}
	names := make([]string, 0, len(expectedNames))
	for name := range expectedNames {
		names = append(names, name)
	}
	sort.Strings(names)
	selected := make([]v1alpha1.NodePolicyStatus, 0, len(names))
	for _, name := range names {
		if node, ok := byName[name]; ok {
			selected = append(selected, node)
		} else {
			selected = append(selected, v1alpha1.NodePolicyStatus{NodeName: name})
		}
	}
	return aggregateEventSourceNodes(selected, now, dependencies, expected.Desired, false)
}

func aggregateEventSourceNodes(nodes []v1alpha1.NodePolicyStatus, now metav1.Time, dependencies []string, desired int, inventoryIncomplete bool) (metav1.Condition, bool) {
	cond := metav1.Condition{Type: v1alpha1.ConditionEventSourcesAvailable, LastTransitionTime: now}
	if desired == 0 {
		desired = len(nodes)
	}
	failures, unknown := make(map[string][]string), make(map[string][]string)
	for _, node := range nodes {
		for _, dependency := range dependencies {
			status, ok := sourceStatusFor(node.EventSources, dependency)
			if !ok || status.Status != metav1.ConditionTrue && status.Status != metav1.ConditionFalse {
				unknown[node.NodeName] = append(unknown[node.NodeName], dependency)
				continue
			}
			if status.Status == metav1.ConditionFalse {
				entry := dependency
				if status.Message != "" {
					entry += ": " + status.Message
				}
				failures[node.NodeName] = append(failures[node.NodeName], entry)
			}
		}
	}
	if len(failures) != 0 {
		reporting, scope := desired, "expected"
		if inventoryIncomplete {
			reporting, scope = len(nodes), "reporting"
		}
		cond.Status, cond.Reason = metav1.ConditionFalse, v1alpha1.ReasonEventSourcesUnavailable
		cond.Message = fmt.Sprintf("required event sources are unavailable on %d of %d %s daemon node(s): %s", len(failures), reporting, scope, truncatedNodeList(sourceNodeEntries(failures)))
		return cond, true
	}
	if inventoryIncomplete || len(unknown) != 0 || len(nodes) < desired {
		cond.Status, cond.Reason = metav1.ConditionUnknown, v1alpha1.ReasonEventSourcesUnknown
		if inventoryIncomplete {
			cond.Message = "event source status is unknown while daemon membership is incomplete"
		} else {
			cond.Message = fmt.Sprintf("required event source status is pending on %d of %d expected daemon node(s): %s", len(unknown), desired, truncatedNodeList(sourceNodeEntries(unknown)))
		}
		return cond, true
	}
	cond.Status, cond.Reason = metav1.ConditionTrue, v1alpha1.ReasonEventSourcesAvailable
	cond.Message = fmt.Sprintf("required event sources are available on all %d expected daemon node(s)", desired)
	return cond, true
}

func sourceNodeEntries(byNode map[string][]string) []string {
	names := make([]string, 0, len(byNode))
	for name := range byNode {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]string, 0, len(names))
	for _, name := range names {
		entries = append(entries, name+": "+strings.Join(byNode[name], ", "))
	}
	return entries
}

func sourceStatusFor(statuses []v1alpha1.EventSourceStatus, name string) (v1alpha1.EventSourceStatus, bool) {
	for _, status := range statuses {
		if status.Name == name {
			return status, true
		}
	}
	return v1alpha1.EventSourceStatus{}, false
}

func (s *StatusWriter) sourceNodes() (ExpectedSourceNodes, bool) {
	s.mu.Lock()
	f := s.expectedSourceNodes
	s.mu.Unlock()
	if f == nil {
		return ExpectedSourceNodes{}, false
	}
	return f(), true
}

// aggregateAvailability is all-true across the nodes reporting the value: one
// node that cannot enforce or observe leaves that node's workloads uncovered
// no matter how many other nodes can. It reports nothing when no node does.
func aggregateAvailability(nodes []v1alpha1.NodePolicyStatus, now metav1.Time,
	condType, trueReason, falseReason string, value func(*v1alpha1.NodePolicyStatus) *bool) (metav1.Condition, bool) {
	var reporting int
	var failing []string
	for i := range nodes {
		v := value(&nodes[i])
		if v == nil {
			continue
		}
		reporting++
		if *v {
			continue
		}
		entry := nodes[i].NodeName
		if nodes[i].Message != "" {
			entry += ": " + nodes[i].Message
		}
		failing = append(failing, entry)
	}
	if reporting == 0 {
		return metav1.Condition{Type: condType}, false
	}
	cond := metav1.Condition{Type: condType, LastTransitionTime: now}
	if len(failing) == 0 {
		cond.Status = metav1.ConditionTrue
		cond.Reason = trueReason
		cond.Message = fmt.Sprintf("available on all %d reporting node(s)", reporting)
		return cond, true
	}
	cond.Status = metav1.ConditionFalse
	cond.Reason = falseReason
	cond.Message = fmt.Sprintf("unavailable on %d of %d reporting node(s): %s",
		len(failing), reporting, truncatedNodeList(failing))
	return cond, true
}

// aggregatePodsMatched is any-true: a policy's pods typically run on a few
// nodes, so the nodes where none are scheduled must not read as a selector
// that matches nothing.
func aggregatePodsMatched(nodes []v1alpha1.NodePolicyStatus, now metav1.Time) (metav1.Condition, bool) {
	var reporting, matching int
	for i := range nodes {
		if nodes[i].PodsMatched == nil {
			continue
		}
		reporting++
		if *nodes[i].PodsMatched {
			matching++
		}
	}
	if reporting == 0 {
		return metav1.Condition{Type: v1alpha1.ConditionPodsMatched}, false
	}
	cond := metav1.Condition{Type: v1alpha1.ConditionPodsMatched, LastTransitionTime: now}
	if matching > 0 {
		cond.Status = metav1.ConditionTrue
		cond.Reason = v1alpha1.ReasonPodsMatched
		cond.Message = fmt.Sprintf("pods match the policy on %d of %d reporting node(s)", matching, reporting)
		return cond, true
	}
	cond.Status = metav1.ConditionFalse
	cond.Reason = v1alpha1.ReasonNoMatchingPods
	cond.Message = fmt.Sprintf("no pod on any of %d reporting node(s) matches the policy's podSelector/namespaceSelector", reporting)
	return cond, true
}

const maxReportedNodes = 5

func truncatedNodeList(entries []string) string {
	if len(entries) > maxReportedNodes {
		entries = append(entries[:maxReportedNodes:maxReportedNodes],
			fmt.Sprintf("and %d more", len(entries)-maxReportedNodes))
	}
	return strings.Join(entries, "; ")
}
