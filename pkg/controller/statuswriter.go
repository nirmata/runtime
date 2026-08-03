package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	v1alpha1client "github.com/nirmata/kyverno-runtime/pkg/client/clientset/versioned"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/events"

	"github.com/go-logr/logr"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

// Condition types and reasons written by the StatusWriter. TargetsValid and
// ObservationAvailable are produced by the managers and merged verbatim.
const (
	// ConditionApplied reports that this node's daemon has the policy loaded,
	// with the reason naming the mode it is running in.
	ConditionApplied = "Applied"

	ReasonEnforcing  = "Enforcing"
	ReasonMonitoring = "Monitoring"
	ReasonNoMode     = "NoMode"

	// ReasonCompileFailed reports a policy whose spec the compiler rejected, so
	// nothing at all was programmed for it.
	ReasonCompileFailed = "CompileFailed"
)

// DefaultStatusFlushInterval is the flush cadence used by the daemon.
const DefaultStatusFlushInterval = 30 * time.Second

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

	mu sync.Mutex
	// policies is keyed by policy UID.
	policies map[string]*policyStatusState
}

// NewStatusWriter builds a StatusWriter for this node. A non-positive interval
// falls back to DefaultStatusFlushInterval.
func NewStatusWriter(client v1alpha1client.Interface, nodeName string, interval time.Duration, log logr.Logger) *StatusWriter {
	if interval <= 0 {
		interval = DefaultStatusFlushInterval
	}
	return &StatusWriter{
		client:   client,
		nodeName: nodeName,
		interval: interval,
		log:      log.WithName("statuswriter"),
		clock:    time.Now,
		policies: make(map[string]*policyStatusState),
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
	st.conditions[ConditionApplied] = s.appliedCondition(res.Mode)
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
	st.conditions[cond.Type] = cond
	st.touch()
}

func (s *StatusWriter) appliedCondition(mode string) metav1.Condition {
	status := metav1.ConditionTrue
	reason := ReasonEnforcing
	message := "the policy is being enforced on this node"
	switch mode {
	case compiler.ModeMonitor:
		reason = ReasonMonitoring
		message = "the policy is observed and reported but never blocks"
	case "":
		status = metav1.ConditionFalse
		reason = ReasonNoMode
		message = "the policy sets no spec.mode, so it is neither enforced nor reported"
	}
	return metav1.Condition{
		Type:               ConditionApplied,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(s.clock()),
	}
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
	conditions []metav1.Condition
	gen        uint64
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
		conds := make([]metav1.Condition, 0, len(st.conditions))
		for _, c := range st.conditions {
			conds = append(conds, c)
		}
		items = append(items, flushItem{
			uid:        uid,
			name:       st.name,
			conditions: conds,
			gen:        st.gen,
		})
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

		setNodeShard(&updated.Status, v1alpha1.NodePolicyStatus{
			NodeName:          s.nodeName,
			LastEvaluatedTime: &now,
		})
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

		if apiequality.Semantic.DeepEqual(before, updated.Status) {
			// nothing to say; skip the write entirely
			return nil
		}

		_, err = rpClient.UpdateStatus(ctx, updated, metav1.UpdateOptions{})
		return err
	})
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
