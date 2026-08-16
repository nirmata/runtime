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

// writeReport creates or updates the Report addressed by key.
func (r *Reporter) writeReport(ctx context.Context, key reportKey, items map[string]*pending) error {
	incoming := r.buildResults(items)
	namespace, name := key.Namespace, key.Name

	existing := &openreportsv1alpha1.Report{}
	err := r.client.Get(ctx, k8stypes.NamespacedName{Namespace: namespace, Name: name}, existing)
	switch {
	case apierrors.IsNotFound(err):
		results, summary, truncated, _ := applyResults(nil, incoming, r.opts.MaxResultsPerReport)
		report := r.newReport(namespace, name)
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

func (r *Reporter) newReport(namespace, name string) *openreportsv1alpha1.Report {
	return &openreportsv1alpha1.Report{
		TypeMeta: metav1.TypeMeta{APIVersion: "openreports.io/v1alpha1", Kind: "Report"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels: map[string]string{
				LabelManagedBy: Source,
				LabelNode:      r.opts.NodeName,
			},
		},
		Source:        Source,
		Configuration: reportConfiguration(r.opts.MaxResultsPerReport),
	}
}

func reportConfiguration(max int) *openreportsv1alpha1.ReportConfiguration {
	return &openreportsv1alpha1.ReportConfiguration{
		Limits: openreportsv1alpha1.Limits{MaxResults: max},
	}
}

// reportNameForPod derives the Report name for a pod. Names over the 63-char
// object-name limit are truncated and suffixed with a hash of the full name,
// so two long pod names sharing a prefix never address the same Report.
func reportNameForPod(podName string) string {
	name := "kyverno-runtime-" + podName
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return strings.TrimRight(name[:54], "-.") + "-" + hex.EncodeToString(sum[:])[:8]
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
