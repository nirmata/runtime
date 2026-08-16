package reporter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Defaults for Options.
const (
	DefaultMaxResultsPerReport = 500
	DefaultFlushInterval       = 10 * time.Second
	// defaultFlushTimeout bounds the final flush performed after ctx is
	// cancelled, which must not use the cancelled context.
	defaultFlushTimeout = 30 * time.Second
	// unknownNode labels reports written by a daemon with no NODE_NAME.
	unknownNode = "unknown"
)

// reportWrite metric label values.
const (
	writeOK      = "ok"
	writeError   = "error"
	writeSkipped = "skipped"
)

// Options configures a Reporter. The zero value is usable: every field has a
// default. Note that no option touches redaction — that is deliberate and
// permanent (DESIGN §4).
type Options struct {
	// NodeName is the value of the node label on every Report this daemon
	// writes.
	NodeName string
	// MaxResultsPerReport caps results per Report (default 500). Reports at
	// the cap carry the truncated-results annotation.
	MaxResultsPerReport int
	// FlushInterval is how often buffered findings are written (default 10s).
	FlushInterval time.Duration
	// Clock is injectable for tests; defaults to time.Now.
	Clock func() time.Time
}

// Reporter buffers findings, deduplicates them by fingerprint, and flushes
// them into namespaced OpenReports Report resources.
type Reporter struct {
	client  client.Client
	log     logr.Logger
	metrics *metrics.Metrics
	opts    Options

	mu sync.Mutex
	// pending maps report -> fingerprint -> accumulated finding.
	pending map[reportKey]map[string]*pending
}

// reportKey addresses one Report: the pod's namespace and the Report name
// derived from the pod's name.
type reportKey struct {
	Namespace string
	Name      string
}

// New creates a Reporter writing through c. m may be nil.
func New(c client.Client, log logr.Logger, m *metrics.Metrics, opts Options) *Reporter {
	if opts.MaxResultsPerReport <= 0 {
		opts.MaxResultsPerReport = DefaultMaxResultsPerReport
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = DefaultFlushInterval
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.NodeName == "" {
		opts.NodeName = unknownNode
		log.V(0).Info("reporter has no node name; reports will carry the unknown node label", "nodeLabel", unknownNode)
	}

	return &Reporter{
		client:  c,
		log:     log,
		metrics: m,
		opts:    opts,
		pending: map[reportKey]map[string]*pending{},
	}
}

// Report enqueues a finding. It never blocks on the API server: repeats of a
// fingerprint merge into the buffered entry (count, firstTimestamp,
// lastTimestamp) and the next flush writes the merged result.
//
// Findings without a usable pod namespace and name are dropped: they cannot
// address a namespaced Report. Attribution normally guarantees both
// (unattributed events are dropped upstream), so this is both a safety net
// and — because an unvalidated value would otherwise be echoed into object
// metadata, bypassing sanitize — part of the redaction boundary.
func (r *Reporter) Report(f Finding) {
	errs := validation.IsDNS1123Label(f.Pod.Namespace)
	if len(errs) == 0 {
		errs = validation.IsDNS1123Subdomain(f.Pod.Name)
	}
	if len(errs) > 0 {
		r.log.V(0).Info("dropping finding with unusable pod identity",
			"policy", sanitize(f.PolicyName), "podUid", sanitize(f.Pod.UID), "reason", errs[0])
		if r.metrics != nil {
			r.metrics.EventsDropped.WithLabelValues("reporter", "unattributed").Inc()
		}
		return
	}

	at := f.Timestamp
	if at.IsZero() {
		at = r.opts.Clock()
	}
	at = at.UTC()

	fp := f.Fingerprint()
	key := reportKey{Namespace: f.Pod.Namespace, Name: reportNameForPod(f.Pod.Name)}

	r.mu.Lock()
	byFingerprint, ok := r.pending[key]
	if !ok {
		byFingerprint = map[string]*pending{}
		r.pending[key] = byFingerprint
	}
	if p, found := byFingerprint[fp]; found {
		p.merge(f, at)
	} else {
		byFingerprint[fp] = &pending{finding: f, count: 1, first: at, last: at}
	}
	r.mu.Unlock()

	// Metric labels and log values are sanitized like everything else this
	// package emits: /metrics and the log stream are outputs too.
	policy := sanitize(f.PolicyName)
	behavior := sanitize(f.Behavior)
	if r.metrics != nil {
		r.metrics.FindingsEmitted.WithLabelValues(policy, behavior).Inc()
	}
	if r.log.V(4).Enabled() {
		r.log.V(4).Info("finding buffered", "policy", policy, "behavior", behavior,
			"pod", sanitize(f.Pod.Name), "namespace", f.Pod.Namespace, "fingerprint", fp,
			"result", normalizeResult(f.Result), "properties", findingProperties(f))
	}
}

// Run flushes buffered findings every FlushInterval until ctx is done, then
// performs one final flush so findings observed just before shutdown are not
// lost. It returns nil on clean shutdown.
func (r *Reporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.opts.FlushInterval)
	defer ticker.Stop()

	r.log.V(2).Info("reporter started", "flushInterval", r.opts.FlushInterval,
		"maxResultsPerReport", r.opts.MaxResultsPerReport)

	for {
		select {
		case <-ctx.Done():
			// The parent context is cancelled, so the final flush needs its
			// own deadline-bounded context to reach the API server.
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultFlushTimeout)
			if err := r.flush(final); err != nil {
				r.log.V(0).Error(err, "final report flush failed")
			}
			cancel()
			r.log.V(2).Info("reporter stopped")
			return nil
		case <-ticker.C:
			if err := r.flush(ctx); err != nil {
				r.log.V(0).Error(err, "report flush failed")
			}
		}
	}
}

// flush writes one Report per (namespace, pod) holding buffered findings. A
// report whose write fails is re-buffered so the next flush retries it.
func (r *Reporter) flush(ctx context.Context) error {
	batch := r.drain()
	if len(batch) == 0 {
		return nil
	}

	keys := make([]reportKey, 0, len(batch))
	for key := range batch {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})

	var errs []error
	for _, key := range keys {
		if err := r.writeReport(ctx, key, batch[key]); err != nil {
			errs = append(errs, err)
			r.requeue(key, batch[key])
		}
	}
	return errors.Join(errs...)
}

// drain removes and returns everything buffered.
func (r *Reporter) drain() map[reportKey]map[string]*pending {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.pending) == 0 {
		return nil
	}
	batch := r.pending
	r.pending = map[reportKey]map[string]*pending{}
	return batch
}

// requeue folds a failed batch back into the buffer without double counting.
func (r *Reporter) requeue(key reportKey, items map[string]*pending) {
	r.mu.Lock()
	defer r.mu.Unlock()

	byFingerprint, ok := r.pending[key]
	if !ok {
		r.pending[key] = items
		return
	}
	for fp, item := range items {
		existing, found := byFingerprint[fp]
		if !found {
			byFingerprint[fp] = item
			continue
		}
		existing.count += item.count
		if item.first.Before(existing.first) {
			existing.first = item.first
		}
		if item.last.After(existing.last) {
			existing.last = item.last
		}
	}
}

// writeReport creates or updates the Report addressed by key. The Report is
// owned by the pod items currently describe, so it is garbage collected with
// that pod rather than persisting indefinitely.
func (r *Reporter) writeReport(ctx context.Context, key reportKey, items map[string]*pending) error {
	incoming := r.buildResults(items)
	namespace, name := key.Namespace, key.Name
	pod := currentPod(items)

	existing := &openreportsv1alpha1.Report{}
	err := r.client.Get(ctx, k8stypes.NamespacedName{Namespace: namespace, Name: name}, existing)
	switch {
	case apierrors.IsNotFound(err):
		results, summary, truncated, _ := applyResults(nil, incoming, r.opts.MaxResultsPerReport)
		report := r.newReport(namespace, name, pod)
		report.Results = results
		report.Summary = summary
		setTruncated(report, truncated)

		if createErr := r.client.Create(ctx, report); createErr != nil {
			r.countWrite(writeError)
			return fmt.Errorf("creating report %s/%s: %w", namespace, name, createErr)
		}
		r.countWrite(writeOK)
		r.log.V(2).Info("report created", "namespace", namespace, "name", name,
			"results", len(results), "truncated", truncated)
		return nil

	case err != nil:
		r.countWrite(writeError)
		return fmt.Errorf("getting report %s/%s: %w", namespace, name, err)
	}

	if incarnation := sanitize(pod.UID); existing.Labels[LabelPodUID] != "" && existing.Labels[LabelPodUID] != incarnation {
		r.log.V(2).Info("report name reused by a new pod incarnation, resetting",
			"namespace", namespace, "name", name)
		existing.Results = nil
	}
	setReportOwner(existing, r.opts.NodeName, pod)

	results, summary, truncated, changed := applyResults(existing.Results, incoming, r.opts.MaxResultsPerReport)
	if !changed {
		r.countWrite(writeSkipped)
		r.log.V(2).Info("report update skipped: no change at capacity",
			"namespace", namespace, "name", name, "results", len(existing.Results))
		return nil
	}

	existing.Source = Source
	existing.Results = results
	existing.Summary = summary
	existing.Configuration = reportConfiguration(r.opts.MaxResultsPerReport)
	setTruncated(existing, truncated)

	if updateErr := r.client.Update(ctx, existing); updateErr != nil {
		r.countWrite(writeError)
		return fmt.Errorf("updating report %s/%s: %w", namespace, name, updateErr)
	}
	r.countWrite(writeOK)
	r.log.V(2).Info("report updated", "namespace", namespace, "name", name,
		"results", len(results), "truncated", truncated)
	return nil
}

// currentPod returns the pod identity of the most recently observed finding
// in items, the same newest-wins rule pending.merge applies within a single
// fingerprint, extended across a whole batch: it is what a Report's owner
// reference and incarnation label should describe.
func currentPod(items map[string]*pending) runtimeevent.PodIdentity {
	var newest *pending
	for _, p := range items {
		if newest == nil || p.last.After(newest.last) {
			newest = p
		}
	}
	return newest.finding.Pod
}

// buildResults renders the buffered findings in deterministic fingerprint
// order so repeated runs produce byte-identical reports.
func (r *Reporter) buildResults(items map[string]*pending) []openreportsv1alpha1.ReportResult {
	fingerprints := make([]string, 0, len(items))
	for fp := range items {
		fingerprints = append(fingerprints, fp)
	}
	sort.Strings(fingerprints)

	results := make([]openreportsv1alpha1.ReportResult, 0, len(fingerprints))
	for _, fp := range fingerprints {
		results = append(results, buildResult(items[fp]))
	}
	return results
}

func (r *Reporter) newReport(namespace, name string, pod runtimeevent.PodIdentity) *openreportsv1alpha1.Report {
	report := &openreportsv1alpha1.Report{
		TypeMeta:      metav1.TypeMeta{APIVersion: "openreports.io/v1alpha1", Kind: "Report"},
		ObjectMeta:    metav1.ObjectMeta{Namespace: namespace, Name: name},
		Source:        Source,
		Configuration: reportConfiguration(r.opts.MaxResultsPerReport),
	}
	setReportOwner(report, r.opts.NodeName, pod)
	return report
}

// setReportOwner (re)stamps the labels and owner reference tying a Report to
// the node writing it and the pod incarnation its results describe. Called on
// both create and update so an update refreshes them exactly like a create
// would, and an owner reference to the pod lets Kubernetes garbage collect
// the Report once that pod is gone instead of it persisting indefinitely.
func setReportOwner(report *openreportsv1alpha1.Report, nodeName string, pod runtimeevent.PodIdentity) {
	if report.Labels == nil {
		report.Labels = map[string]string{}
	}
	report.Labels[LabelManagedBy] = Source
	report.Labels[LabelNode] = nodeName
	report.Labels[LabelPodUID] = sanitize(pod.UID)
	report.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "v1",
		Kind:       "Pod",
		Name:       sanitize(pod.Name),
		UID:        k8stypes.UID(sanitize(pod.UID)),
	}}
}

func reportConfiguration(max int) *openreportsv1alpha1.ReportConfiguration {
	return &openreportsv1alpha1.ReportConfiguration{
		Limits: openreportsv1alpha1.Limits{MaxResults: max},
	}
}

// reportNameForPod derives the Report name for a pod. Names over the 63-char
// object-name limit are truncated and suffixed with a 64-bit hash of the full
// name, so two long pod names sharing a prefix collide only astronomically
// rarely rather than at the one-in-a-few-thousand rate an 8-hex-digit (32-bit)
// suffix would.
func reportNameForPod(podName string) string {
	name := "kyverno-runtime-" + podName
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return strings.TrimRight(name[:46], "-.") + "-" + hex.EncodeToString(sum[:])[:16]
}

// setTruncated adds or clears the truncation annotation.
func setTruncated(report *openreportsv1alpha1.Report, truncated bool) {
	if !truncated {
		delete(report.Annotations, AnnotationTruncatedResults)
		if len(report.Annotations) == 0 {
			report.Annotations = nil
		}
		return
	}
	if report.Annotations == nil {
		report.Annotations = map[string]string{}
	}
	report.Annotations[AnnotationTruncatedResults] = "true"
}

func (r *Reporter) countWrite(result string) {
	if r.metrics == nil {
		return
	}
	r.metrics.ReportWrites.WithLabelValues(result).Inc()
}
