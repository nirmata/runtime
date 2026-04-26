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

	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
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
	propertyWindow        = "window"
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

	eventMu      sync.Mutex
	eventWindows map[string]eventWindow
}

// ReporterOptions controls buffering and flush behavior.
type ReporterOptions struct {
	BufferInterval   time.Duration
	MaxBufferedCount int
	// MaxReportResults caps the number of results kept in a Report.
	// If zero the package-level maxPolicyReportResults constant is used.
	MaxReportResults int
	// SuppressionCooldown applies per-fingerprint rolling windows used for
	// rate limiting repeated duplicate findings.
	SuppressionCooldown time.Duration
	// SuppressionBurst controls the max allowed duplicate updates for a
	// fingerprint within a cooldown window. Zero disables suppression.
	SuppressionBurst int
	// EventCooldown applies per-fingerprint rolling windows for emitted
	// Kubernetes Events.
	EventCooldown time.Duration
	// EventBurst controls max Events emitted per fingerprint in one cooldown
	// window. Zero disables Event rate limiting.
	EventBurst int
}

type suppressionOptions struct {
	cooldown time.Duration
	burst    int
	now      func() time.Time
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

type eventWindow struct {
	start time.Time
	count int
}

// NewK8sReporter creates a new K8sReporter.
func NewK8sReporter(c client.Client) *K8sReporter {
	return NewK8sReporterWithOptions(c, ReporterOptions{})
}

// NewK8sReporterWithOptions creates a new K8sReporter with buffering options.
func NewK8sReporterWithOptions(c client.Client, opts ReporterOptions) *K8sReporter {
	r := &K8sReporter{client: c, opts: opts, eventWindows: map[string]eventWindow{}}
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
	existing := &openreportsv1alpha1.Report{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Pod.Namespace, Name: reportName}, existing)

	results := buildPolicyReportResults(req.Pod, req.Policy, req.Findings)

	if apierrors.IsNotFound(err) {
		started := time.Now()
		merged, _, _ := mergePolicyReportResults(nil, results, suppressionOptions{
			cooldown: r.opts.SuppressionCooldown,
			burst:    r.opts.SuppressionBurst,
		})
		bounded := truncatePolicyReportResults(merged, r.maxResults())
		obj := &openreportsv1alpha1.Report{
			TypeMeta: metav1.TypeMeta{APIVersion: "openreports.io/v1alpha1", Kind: "Report"},
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
			Source:  "kyverno-runtime",
			Scope:   podReference(req.Pod),
			Results: bounded,
			Summary: summarizePolicyReportResults(bounded),
		}
		setTruncatedAnnotation(obj, len(merged), r.maxResults())
		if err := r.client.Create(ctx, obj); err != nil {
			observability.IncReporterWrite("create", "error")
			observability.IncSinkFailure("kubernetes_report")
			observability.ObserveReporterOutputLatency("create", time.Since(started).Seconds())
			return err
		}
		r.emitKubernetesEvents(ctx, req, merged)
		observability.AddAlertsEmitted(len(merged))
		observability.IncReporterWrite("create", "success")
		observability.ObserveReporterOutputLatency("create", time.Since(started).Seconds())
		return nil
	}
	if err != nil {
		return err
	}

	merged, addedNew, suppressed := mergePolicyReportResults(existing.Results, results, suppressionOptions{
		cooldown: r.opts.SuppressionCooldown,
		burst:    r.opts.SuppressionBurst,
	})
	if suppressed > 0 {
		observability.AddReporterFindingsSuppressed("cooldown_burst", suppressed)
	}
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
	started := time.Now()
	if err := r.client.Update(ctx, existing); err != nil {
		observability.IncReporterWrite("update", "error")
		observability.IncSinkFailure("kubernetes_report")
		observability.ObserveReporterOutputLatency("update", time.Since(started).Seconds())
		return err
	}
	r.emitKubernetesEvents(ctx, req, merged)
	observability.AddAlertsEmitted(len(merged))
	observability.IncReporterWrite("update", "success")
	observability.ObserveReporterOutputLatency("update", time.Since(started).Seconds())
	return nil
}

func (r *K8sReporter) emitKubernetesEvents(ctx context.Context, req ReportRequest, results []openreportsv1alpha1.ReportResult) {
	for _, result := range results {
		fp := result.Properties[propertyFingerprint]
		if fp == "" {
			fp = findingFingerprint(req.Pod, req.Policy, v1alpha1.RuleFinding{RuleName: result.Rule, Fields: result.Properties})
		}
		if !r.shouldEmitEvent(fp) {
			observability.IncReporterEvent("rate_limited")
			continue
		}

		now := metav1.NewTime(time.Now().UTC())
		eventType := corev1.EventTypeWarning
		if strings.ToLower(string(result.Result)) == "pass" {
			eventType = corev1.EventTypeNormal
		}
		e := &corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "kyverno-runtime-",
				Namespace:    req.Pod.Namespace,
			},
			InvolvedObject: *podReference(req.Pod),
			Type:           eventType,
			Reason:         "RuntimeDetection",
			Message:        result.Description,
			Source:         corev1.EventSource{Component: "kyverno-runtime"},
			FirstTimestamp: now,
			LastTimestamp:  now,
			Count:          1,
		}
		if err := r.client.Create(ctx, e); err != nil {
			observability.IncReporterEvent("error")
			observability.IncSinkFailure("kubernetes_event")
			continue
		}
		observability.IncReporterEvent("emitted")
	}
}

func (r *K8sReporter) shouldEmitEvent(fingerprint string) bool {
	if fingerprint == "" {
		return true
	}
	if r.opts.EventCooldown <= 0 || r.opts.EventBurst <= 0 {
		return true
	}
	now := time.Now().UTC()

	r.eventMu.Lock()
	defer r.eventMu.Unlock()

	window, ok := r.eventWindows[fingerprint]
	if !ok || now.Sub(window.start) >= r.opts.EventCooldown {
		r.eventWindows[fingerprint] = eventWindow{start: now, count: 1}
		return true
	}
	if window.count >= r.opts.EventBurst {
		return false
	}
	window.count++
	r.eventWindows[fingerprint] = window
	return true
}

// setTruncatedAnnotation records the number of dropped results on the report
// via an annotation so operators can detect when the limit has been hit.
func setTruncatedAnnotation(report *openreportsv1alpha1.Report, total, max int) {
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

func buildPolicyReportResults(pod *corev1.Pod, policy *v1alpha1.RuntimePolicy, findings []v1alpha1.RuleFinding) []openreportsv1alpha1.ReportResult {
	results := make([]openreportsv1alpha1.ReportResult, 0, len(findings))
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
		properties[propertyWindow] = encodeWindowState(now, 1)
		if containerName := extractContainerName(finding.Fields); containerName != "" {
			properties[propertyContainerName] = containerName
		}

		result := openreportsv1alpha1.ReportResult{
			Source:      "kyverno-runtime",
			Policy:      policy.Name,
			Rule:        finding.RuleName,
			Subjects:    []corev1.ObjectReference{*podReference(pod)},
			Description: finding.Message,
			Result:      reportResultForSeverity(finding.Severity),
			Scored:      true,
			Severity:    openreportsv1alpha1.ResultSeverity(strings.ToLower(strings.TrimSpace(finding.Severity))),
			Category:    "Runtime Security",
			Timestamp:   metav1.Timestamp{Seconds: now.Unix()},
			Properties:  properties,
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
// The third return value is the number of suppressed duplicate updates.
func mergePolicyReportResults(existing []openreportsv1alpha1.ReportResult, incoming []openreportsv1alpha1.ReportResult, opts suppressionOptions) ([]openreportsv1alpha1.ReportResult, bool, int) {
	merged := append([]openreportsv1alpha1.ReportResult(nil), existing...)
	indexByFingerprint := map[string]int{}
	addedNew := false
	suppressed := 0
	now := time.Now().UTC()
	if opts.now != nil {
		now = opts.now().UTC()
	}

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

		windowStart, windowCount := currentWindowState(existingResult, now, opts.cooldown)
		if opts.cooldown > 0 && opts.burst > 0 && now.Sub(windowStart) < opts.cooldown && windowCount >= opts.burst {
			suppressed++
			continue
		}
		if opts.cooldown > 0 {
			if now.Sub(windowStart) < opts.cooldown {
				windowCount += incomingCount
			} else {
				windowStart = now
				windowCount = incomingCount
			}
		}

		if existingResult.Properties == nil {
			existingResult.Properties = map[string]string{}
		}
		existingResult.Properties[propertyFingerprint] = fingerprint
		existingResult.Properties[propertyCount] = strconv.Itoa(existingCount + incomingCount)
		if opts.cooldown > 0 {
			existingResult.Properties[propertyWindow] = encodeWindowState(windowStart, windowCount)
		}

		firstSeen := existingResult.Properties[propertyFirstSeen]
		if firstSeen == "" {
			firstSeen = candidate.Properties[propertyFirstSeen]
		}
		existingResult.Properties[propertyFirstSeen] = firstSeen
		existingResult.Properties[propertyLastSeen] = candidate.Properties[propertyLastSeen]

		existingResult.Timestamp = candidate.Timestamp
		merged[idx] = existingResult
	}

	return merged, addedNew, suppressed
}

func currentWindowState(result openreportsv1alpha1.ReportResult, now time.Time, cooldown time.Duration) (time.Time, int) {
	if cooldown <= 0 {
		return now, parseCount(result.Properties[propertyCount])
	}
	if start, count, ok := decodeWindowState(result.Properties[propertyWindow]); ok {
		return start, count
	}
	if lastSeen, err := time.Parse(time.RFC3339, result.Properties[propertyLastSeen]); err == nil {
		return lastSeen.UTC(), parseCount(result.Properties[propertyCount])
	}
	return now, parseCount(result.Properties[propertyCount])
}

func encodeWindowState(start time.Time, count int) string {
	if count < 1 {
		count = 1
	}
	return start.UTC().Format(time.RFC3339) + "|" + strconv.Itoa(count)
}

func decodeWindowState(raw string) (time.Time, int, bool) {
	parts := strings.Split(raw, "|")
	if len(parts) != 2 {
		return time.Time{}, 0, false
	}
	start, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[0]))
	if err != nil {
		return time.Time{}, 0, false
	}
	count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || count < 1 {
		return time.Time{}, 0, false
	}
	return start.UTC(), count, true
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

func reportResultForSeverity(severity string) openreportsv1alpha1.Result {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info", "low":
		return openreportsv1alpha1.Result("warn")
	default:
		return openreportsv1alpha1.Result("fail")
	}
}

func summarizePolicyReportResults(results []openreportsv1alpha1.ReportResult) openreportsv1alpha1.ReportSummary {
	summary := openreportsv1alpha1.ReportSummary{}
	for _, result := range results {
		switch strings.ToLower(string(result.Result)) {
		case "pass":
			summary.Pass++
		case "warn":
			summary.Warn++
		case "skip":
			summary.Skip++
		case "error":
			summary.Error++
		default:
			summary.Fail++
		}
	}
	return summary
}

func truncatePolicyReportResults(results []openreportsv1alpha1.ReportResult, max int) []openreportsv1alpha1.ReportResult {
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
