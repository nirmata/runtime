package pipeline

import (
	"context"
	"crypto/sha1"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	policyreportv1alpha2 "github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/observability"
)

const maxPolicyReportResults = 1000

const defaultFlushTimeout = 30 * time.Second

const (
	propertyFingerprint   = "fingerprint"
	propertyCount         = "count"
	propertyFirstSeen     = "firstTimestamp"
	propertyLastSeen      = "lastTimestamp"
	propertyContainerName = "container"

	annotationTruncatedResults = "runtime.kyverno.io/truncated-results"
)

// K8sReporter writes PolicyReport resources to Kubernetes.
type K8sReporter struct {
	client client.Client
	opts   ReporterOptions

	mu            sync.Mutex
	buffered      map[reportBufferKey]*bufferedReport
	bufferedCount int
	flushTicker   *time.Ticker
}

// ReporterOptions controls buffering and flush behavior.
type ReporterOptions struct {
	BufferInterval   time.Duration
	MaxBufferedCount int
	// MaxReportResults caps the number of results kept in a PolicyReport.
	// If zero the package-level maxPolicyReportResults constant is used.
	MaxReportResults int
}

type reportBufferKey struct {
	namespace string
	pod       string
	policy    string
}

type bufferedReport struct {
	pod      *corev1.Pod
	policy   *v1alpha1.RuntimePolicy
	findings []v1alpha1.RuleFinding
}

// NewK8sReporter creates a new K8sReporter.
func NewK8sReporter(c client.Client) *K8sReporter {
	return NewK8sReporterWithOptions(c, ReporterOptions{})
}

// NewK8sReporterWithOptions creates a new K8sReporter with buffering options.
func NewK8sReporterWithOptions(c client.Client, opts ReporterOptions) *K8sReporter {
	r := &K8sReporter{client: c, opts: opts}
	if opts.BufferInterval > 0 && opts.MaxBufferedCount > 0 {
		r.buffered = map[reportBufferKey]*bufferedReport{}
		r.flushTicker = time.NewTicker(opts.BufferInterval)
		go r.runFlushLoop()
	}
	return r
}

// Report writes or updates a PolicyReport for the given findings.
func (r *K8sReporter) Report(ctx context.Context, req ReportRequest) error {
	if len(req.Findings) == 0 {
		return nil
	}

	if !r.bufferingEnabled() {
		return r.reportNow(ctx, req)
	}

	toFlush := r.bufferRequest(req)
	if len(toFlush) == 0 {
		return nil
	}

	return r.flushBatch(ctx, toFlush)
}

func (r *K8sReporter) maxResults() int {
	if r.opts.MaxReportResults > 0 {
		return r.opts.MaxReportResults
	}
	return maxPolicyReportResults
}

func (r *K8sReporter) reportNow(ctx context.Context, req ReportRequest) error {

	reportName := reportName(req.Pod.Name, req.Policy.Name)
	existing := &policyreportv1alpha2.PolicyReport{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Pod.Namespace, Name: reportName}, existing)

	results := buildPolicyReportResults(req.Pod, req.Policy, req.Findings)

	if apierrors.IsNotFound(err) {
		merged, _ := mergePolicyReportResults(nil, results)
		bounded := truncatePolicyReportResults(merged, r.maxResults())
		obj := &policyreportv1alpha2.PolicyReport{
			TypeMeta: metav1.TypeMeta{APIVersion: policyreportv1alpha2.SchemeGroupVersion.String(), Kind: "PolicyReport"},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: req.Pod.Namespace,
				Name:      reportName,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "kyverno-runtime",
					"runtime.kyverno.io/policy":    req.Policy.Name,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       req.Pod.Name,
					UID:        req.Pod.UID,
				}},
			},
			Scope:   podReference(req.Pod),
			Results: bounded,
			Summary: summarizePolicyReportResults(bounded),
		}
		setTruncatedAnnotation(obj, len(merged), r.maxResults())
		if err := r.client.Create(ctx, obj); err != nil {
			observability.IncReporterWrite("create", "error")
			return err
		}
		observability.IncReporterWrite("create", "success")
		return nil
	}
	if err != nil {
		return err
	}

	merged, addedNew := mergePolicyReportResults(existing.Results, results)
	// When the report is already at capacity and the incoming events are all
	// duplicates of known fingerprints (pure count increments), skip the
	// Kubernetes API Update to reduce API server churn. New distinct events
	// always trigger an update regardless.
	atMax := len(existing.Results) >= r.maxResults()
	if atMax && !addedNew {
		observability.IncReporterUpdateSkipped("at_capacity_duplicates")
		return nil
	}

	bounded := truncatePolicyReportResults(merged, r.maxResults())
	setTruncatedAnnotation(existing, len(merged), r.maxResults())
	existing.Results = bounded
	existing.Summary = summarizePolicyReportResults(existing.Results)
	if err := r.client.Update(ctx, existing); err != nil {
		observability.IncReporterWrite("update", "error")
		return err
	}
	observability.IncReporterWrite("update", "success")
	return nil
}

// setTruncatedAnnotation records the number of dropped results on the report
// via an annotation so operators can detect when the limit has been hit.
func setTruncatedAnnotation(report *policyreportv1alpha2.PolicyReport, total, max int) {
	if total <= max {
		// Remove a stale annotation if the report is no longer truncated.
		if report.Annotations != nil {
			delete(report.Annotations, annotationTruncatedResults)
		}
		return
	}
	if report.Annotations == nil {
		report.Annotations = map[string]string{}
	}
	report.Annotations[annotationTruncatedResults] = strconv.Itoa(total - max)
}

func (r *K8sReporter) bufferingEnabled() bool {
	return r.opts.BufferInterval > 0 && r.opts.MaxBufferedCount > 0
}

func (r *K8sReporter) bufferRequest(req ReportRequest) []ReportRequest {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := reportBufferKey{namespace: req.Pod.Namespace, pod: req.Pod.Name, policy: req.Policy.Name}
	bucket, found := r.buffered[key]
	if !found {
		podCopy := *req.Pod
		policyCopy := *req.Policy
		bucket = &bufferedReport{pod: &podCopy, policy: &policyCopy}
		r.buffered[key] = bucket
	}
	bucket.findings = append(bucket.findings, req.Findings...)
	r.bufferedCount += len(req.Findings)

	if r.bufferedCount < r.opts.MaxBufferedCount {
		return nil
	}

	return r.snapshotAndResetLocked()
}

func (r *K8sReporter) runFlushLoop() {
	for range r.flushTicker.C {
		ctx, cancel := context.WithTimeout(context.Background(), defaultFlushTimeout)
		if err := r.flushBatch(ctx, r.snapshotAndReset()); err != nil {
			log.Log.Error(err, "failed to flush buffered policy reports")
		}
		cancel()
	}
}

func (r *K8sReporter) snapshotAndReset() []ReportRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotAndResetLocked()
}

func (r *K8sReporter) snapshotAndResetLocked() []ReportRequest {
	if len(r.buffered) == 0 {
		return nil
	}

	batch := make([]ReportRequest, 0, len(r.buffered))
	for _, item := range r.buffered {
		batch = append(batch, ReportRequest{
			Pod:      item.pod,
			Policy:   item.policy,
			Findings: append([]v1alpha1.RuleFinding(nil), item.findings...),
		})
	}

	r.buffered = map[reportBufferKey]*bufferedReport{}
	r.bufferedCount = 0
	return batch
}

func (r *K8sReporter) flushBatch(ctx context.Context, batch []ReportRequest) error {
	for _, req := range batch {
		if err := r.reportNow(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func reportName(podName, policyName string) string {
	hash := sha1.Sum([]byte(fmt.Sprintf("%s-%s", podName, policyName)))
	return fmt.Sprintf("%s-%x", podName, hash[:5])
}

func podReference(pod *corev1.Pod) *corev1.ObjectReference {
	return &corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "Pod",
		Namespace:  pod.Namespace,
		Name:       pod.Name,
		UID:        pod.UID,
	}
}

func buildPolicyReportResults(pod *corev1.Pod, policy *v1alpha1.RuntimePolicy, findings []v1alpha1.RuleFinding) []policyreportv1alpha2.PolicyReportResult {
	results := make([]policyreportv1alpha2.PolicyReportResult, 0, len(findings))
	for _, finding := range findings {
		now := time.Now().UTC()
		nowRFC3339 := now.Format(time.RFC3339)

		properties := make(map[string]string, len(finding.Fields)+5)
		for key, value := range finding.Fields {
			cleanValue := sanitizeReportPropertyValue(value)
			if cleanValue == "" {
				continue
			}
			properties[key] = cleanValue
		}
		if finding.EventType != "" {
			properties["eventType"] = finding.EventType
		}

		fingerprint := findingFingerprint(pod, policy, finding)
		properties[propertyFingerprint] = fingerprint
		properties[propertyCount] = "1"
		properties[propertyFirstSeen] = nowRFC3339
		properties[propertyLastSeen] = nowRFC3339
		if containerName := extractContainerName(finding.Fields); containerName != "" {
			properties[propertyContainerName] = containerName
		}

		result := policyreportv1alpha2.PolicyReportResult{
			Source:     "kyverno-runtime",
			Policy:     policy.Name,
			Rule:       finding.RuleName,
			Resources:  []corev1.ObjectReference{*podReference(pod)},
			Message:    finding.Message,
			Result:     reportResultForSeverity(finding.Severity),
			Scored:     true,
			Severity:   policyreportv1alpha2.PolicySeverity(strings.ToLower(strings.TrimSpace(finding.Severity))),
			Category:   "Runtime Security",
			Timestamp:  metav1.Timestamp{Seconds: now.Unix()},
			Properties: properties,
		}
		results = append(results, result)
	}
	return results
}

// sanitizeReportPropertyValue cleans low-level gadget field values so report
// properties are human-readable.
func sanitizeReportPropertyValue(value string) string {
	if value == "" {
		return ""
	}

	// Most gadget strings are C-style buffers with trailing NUL padding.
	if idx := strings.IndexByte(value, 0); idx >= 0 {
		value = value[:idx]
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r == utf8.RuneError {
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}

	return strings.TrimSpace(b.String())
}

// mergePolicyReportResults merges incoming results into existing ones,
// deduplicating by fingerprint. The returned bool is true when at least one
// new fingerprint was added (i.e. the report structurally changed).
func mergePolicyReportResults(existing []policyreportv1alpha2.PolicyReportResult, incoming []policyreportv1alpha2.PolicyReportResult) ([]policyreportv1alpha2.PolicyReportResult, bool) {
	merged := append([]policyreportv1alpha2.PolicyReportResult(nil), existing...)
	indexByFingerprint := map[string]int{}
	addedNew := false

	for i, result := range merged {
		if fingerprint := result.Properties[propertyFingerprint]; fingerprint != "" {
			indexByFingerprint[fingerprint] = i
		}
	}

	for _, candidate := range incoming {
		fingerprint := candidate.Properties[propertyFingerprint]
		if fingerprint == "" {
			merged = append(merged, candidate)
			addedNew = true
			continue
		}

		idx, found := indexByFingerprint[fingerprint]
		if !found {
			indexByFingerprint[fingerprint] = len(merged)
			merged = append(merged, candidate)
			addedNew = true
			continue
		}

		existingResult := merged[idx]
		existingCount := parseCount(existingResult.Properties[propertyCount])
		incomingCount := parseCount(candidate.Properties[propertyCount])

		if existingResult.Properties == nil {
			existingResult.Properties = map[string]string{}
		}
		existingResult.Properties[propertyFingerprint] = fingerprint
		existingResult.Properties[propertyCount] = strconv.Itoa(existingCount + incomingCount)

		firstSeen := existingResult.Properties[propertyFirstSeen]
		if firstSeen == "" {
			firstSeen = candidate.Properties[propertyFirstSeen]
		}
		existingResult.Properties[propertyFirstSeen] = firstSeen
		existingResult.Properties[propertyLastSeen] = candidate.Properties[propertyLastSeen]

		existingResult.Timestamp = candidate.Timestamp
		merged[idx] = existingResult
	}

	return merged, addedNew
}

func parseCount(raw string) int {
	if raw == "" {
		return 1
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 {
		return 1
	}
	return parsed
}

func findingFingerprint(pod *corev1.Pod, policy *v1alpha1.RuntimePolicy, finding v1alpha1.RuleFinding) string {
	matched := serializeMatchedFields(finding.Fields)
	container := extractContainerName(finding.Fields)
	raw := strings.Join([]string{
		policy.Name,
		finding.RuleName,
		pod.Namespace,
		pod.Name,
		container,
		matched,
	}, "|")
	hash := sha1.Sum([]byte(raw))
	return fmt.Sprintf("%x", hash)
}

func serializeMatchedFields(fields map[string]string) string {
	if len(fields) == 0 {
		return ""
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if !includeInFingerprint(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := sanitizeReportPropertyValue(fields[key])
		if value == "" {
			continue
		}
		parts = append(parts, key+"="+value)
	}
	return strings.Join(parts, ";")
}

func includeInFingerprint(key string) bool {
	if key == "" {
		return false
	}

	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}

	if normalized == "timestamp" || normalized == "timestamp_raw" {
		return false
	}
	if strings.HasSuffix(normalized, "_raw") {
		return false
	}
	if normalized == "ustack" || strings.HasPrefix(normalized, "ustack.") {
		return false
	}

	switch normalized {
	case "proc.pid", "proc.tid", "proc.parent.pid", "proc.parent.tid", "proc.mntns_id", "fd":
		return false
	default:
		return true
	}
}

func extractContainerName(fields map[string]string) string {
	if len(fields) == 0 {
		return ""
	}
	for _, key := range []string{"container", "container.name", "k8s.container.name", "containerName"} {
		if name := strings.TrimSpace(fields[key]); name != "" {
			return name
		}
	}
	return ""
}

func reportResultForSeverity(severity string) policyreportv1alpha2.PolicyResult {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info", "low":
		return policyreportv1alpha2.StatusWarn
	default:
		return policyreportv1alpha2.StatusFail
	}
}

func summarizePolicyReportResults(results []policyreportv1alpha2.PolicyReportResult) policyreportv1alpha2.PolicyReportSummary {
	summary := policyreportv1alpha2.PolicyReportSummary{}
	for _, result := range results {
		switch result.Result {
		case policyreportv1alpha2.StatusPass:
			summary.Pass++
		case policyreportv1alpha2.StatusWarn:
			summary.Warn++
		case policyreportv1alpha2.StatusSkip:
			summary.Skip++
		case policyreportv1alpha2.StatusError:
			summary.Error++
		default:
			summary.Fail++
		}
	}
	return summary
}

func truncatePolicyReportResults(results []policyreportv1alpha2.PolicyReportResult, max int) []policyreportv1alpha2.PolicyReportResult {
	if len(results) <= max {
		return results
	}
	dropped := len(results) - max
	observability.AddReporterResultsTruncated(dropped)
	log.Log.V(1).Info("truncating policy report results",
		"total", len(results), "limit", max, "dropped", dropped)
	// Sort by last-seen timestamp descending so the most recent events are
	// retained when the result set is trimmed.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Properties[propertyLastSeen] > results[j].Properties[propertyLastSeen]
	})
	return results[:max]
}
