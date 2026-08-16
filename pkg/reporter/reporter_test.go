package reporter

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/metrics"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/google/go-cmp/cmp"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// fixedTime is the injected clock value for every test in this package: no
// test ever sleeps or reads the wall clock.
var fixedTime = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := openreportsv1alpha1.Install(s); err != nil {
		t.Fatalf("adding openreports to scheme: %v", err)
	}
	return s
}

// recordingClient counts API calls so tests can assert that no-op flushes
// really do not touch the API server, and can inject write failures.
type recordingClient struct {
	client.Client
	gets, creates, updates int
	failCreate             error
	failUpdate             error
}

func newRecordingClient(t *testing.T, objs ...client.Object) *recordingClient {
	t.Helper()
	rc := &recordingClient{}
	rc.Client = fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				rc.gets++
				return c.Get(ctx, key, obj, opts...)
			},
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				rc.creates++
				if rc.failCreate != nil {
					err := rc.failCreate
					rc.failCreate = nil
					return err
				}
				return c.Create(ctx, obj, opts...)
			},
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				rc.updates++
				if rc.failUpdate != nil {
					err := rc.failUpdate
					rc.failUpdate = nil
					return err
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()
	return rc
}

func testLogger(t *testing.T) logr.Logger { return testr.New(t) }

// newTestReporter wires a Reporter with a fixed clock and fresh metrics.
func newTestReporter(t *testing.T, c client.Client, opts Options) (*Reporter, *metrics.Metrics) {
	t.Helper()
	if opts.NodeName == "" {
		opts.NodeName = "node-a"
	}
	if opts.Clock == nil {
		opts.Clock = func() time.Time { return fixedTime }
	}
	m := metrics.New(prometheus.NewRegistry())
	return New(c, testLogger(t), m, opts), m
}

// listReports returns every Report the client holds, sorted by namespace.
func listReports(t *testing.T, c client.Client) []openreportsv1alpha1.Report {
	t.Helper()
	var list openreportsv1alpha1.ReportList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("listing reports: %v", err)
	}
	sort.Slice(list.Items, func(i, j int) bool {
		if list.Items[i].Namespace != list.Items[j].Namespace {
			return list.Items[i].Namespace < list.Items[j].Namespace
		}
		return list.Items[i].Name < list.Items[j].Name
	})
	return list.Items
}

func getReport(t *testing.T, c client.Client, namespace, name string) *openreportsv1alpha1.Report {
	t.Helper()
	var report openreportsv1alpha1.Report
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, &report); err != nil {
		t.Fatalf("getting report %s/%s: %v", namespace, name, err)
	}
	return &report
}

// findingIn returns a distinct finding for the given namespace and pod.
func findingIn(namespace, podUID string, at time.Time) Finding {
	return Finding{
		PolicyName: "block-egress",
		PolicyUID:  "policy-uid-1",
		Behavior:   "network",
		Result:     ResultFail,
		Message:    "egress denied",
		Pod: runtimeevent.PodIdentity{
			UID:       podUID,
			Namespace: namespace,
			Name:      "pod-" + podUID,
			Container: "app",
			NodeName:  "node-a",
		},
		Net:       &NetSummary{DestIP: "1.2.3.4"},
		Timestamp: at,
	}
}

func TestWritesOneReportPerPod(t *testing.T) {
	c := newRecordingClient(t)
	r, m := newTestReporter(t, c, Options{NodeName: "node-a"})

	r.Report(findingIn("default", "pod-1", fixedTime))
	r.Report(findingIn("default", "pod-2", fixedTime))
	r.Report(findingIn("kube-system", "pod-3", fixedTime))

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	reports := listReports(t, c)
	if len(reports) != 3 {
		t.Fatalf("wrote %d reports, want 3 (one per pod)", len(reports))
	}

	gotKeys := []string{
		reports[0].Namespace + "/" + reports[0].Name,
		reports[1].Namespace + "/" + reports[1].Name,
		reports[2].Namespace + "/" + reports[2].Name,
	}
	wantKeys := []string{
		"default/kyverno-runtime-pod-pod-1",
		"default/kyverno-runtime-pod-pod-2",
		"kube-system/kyverno-runtime-pod-pod-3",
	}
	if diff := cmp.Diff(wantKeys, gotKeys); diff != "" {
		t.Errorf("report names (-want +got):\n%s", diff)
	}

	def := reports[0]
	if def.Source != Source {
		t.Errorf("report source = %q, want %q", def.Source, Source)
	}
	if len(def.Results) != 1 {
		t.Errorf("pod-1 report holds %d results, want 1", len(def.Results))
	}
	if def.Summary.Fail != 1 {
		t.Errorf("pod-1 report summary.Fail = %d, want 1", def.Summary.Fail)
	}
	if got := def.Labels[LabelNode]; got != "node-a" {
		t.Errorf("report node label = %q, want node-a", got)
	}
	if got := def.Labels[LabelManagedBy]; got != Source {
		t.Errorf("report managed-by label = %q, want %q", got, Source)
	}
	if def.Configuration == nil || def.Configuration.Limits.MaxResults != DefaultMaxResultsPerReport {
		t.Errorf("report configuration = %+v, want maxResults %d", def.Configuration, DefaultMaxResultsPerReport)
	}
	if _, ok := def.Annotations[AnnotationTruncatedResults]; ok {
		t.Error("untruncated report carries the truncation annotation")
	}
	if got := testutil.ToFloat64(m.ReportWrites.WithLabelValues(writeOK)); got != 3 {
		t.Errorf("ReportWrites{ok} = %v, want 3", got)
	}

	// Another pod's findings never touch an existing pod's report.
	r.Report(findingIn("default", "pod-9", fixedTime))
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush pod-9: %v", err)
	}
	if reports := listReports(t, c); len(reports) != 4 {
		t.Fatalf("wrote %d reports after pod-9 flush, want 4", len(reports))
	}
	if got := len(getReport(t, c, "default", "kyverno-runtime-pod-pod-1").Results); got != 1 {
		t.Errorf("pod-1 report has %d results after pod-9 flush, want 1", got)
	}
}

func TestReportDedupMergesCountAndTimestamps(t *testing.T) {
	c := newRecordingClient(t)
	r, _ := newTestReporter(t, c, Options{NodeName: "node-a"})

	t1 := fixedTime
	t2 := fixedTime.Add(time.Minute)
	t3 := fixedTime.Add(2 * time.Minute)

	// Deliberately out of order: first/last must be min/max, not first/last seen.
	r.Report(findingIn("default", "pod-1", t2))
	r.Report(findingIn("default", "pod-1", t1))
	r.Report(findingIn("default", "pod-1", t3))

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	report := getReport(t, c, "default", "kyverno-runtime-pod-pod-1")
	if len(report.Results) != 1 {
		t.Fatalf("report holds %d results, want 1 (deduplicated)", len(report.Results))
	}
	props := report.Results[0].Properties
	if props[propCount] != "3" {
		t.Errorf("count = %q, want 3", props[propCount])
	}
	if props[propFirstTimestamp] != t1.Format(time.RFC3339) {
		t.Errorf("firstTimestamp = %q, want %q", props[propFirstTimestamp], t1.Format(time.RFC3339))
	}
	if props[propLastTimestamp] != t3.Format(time.RFC3339) {
		t.Errorf("lastTimestamp = %q, want %q", props[propLastTimestamp], t3.Format(time.RFC3339))
	}
	if props[propFingerprint] != findingIn("default", "pod-1", t1).Fingerprint() {
		t.Error("fingerprint property does not match Finding.Fingerprint()")
	}

	// A later flush merges into the stored result rather than appending.
	t4 := fixedTime.Add(time.Hour)
	r.Report(findingIn("default", "pod-1", t4))
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}

	report = getReport(t, c, "default", "kyverno-runtime-pod-pod-1")
	if len(report.Results) != 1 {
		t.Fatalf("report holds %d results after second flush, want 1", len(report.Results))
	}
	props = report.Results[0].Properties
	if props[propCount] != "4" {
		t.Errorf("count after second flush = %q, want 4", props[propCount])
	}
	if props[propFirstTimestamp] != t1.Format(time.RFC3339) {
		t.Errorf("firstTimestamp after second flush = %q, want %q", props[propFirstTimestamp], t1.Format(time.RFC3339))
	}
	if props[propLastTimestamp] != t4.Format(time.RFC3339) {
		t.Errorf("lastTimestamp after second flush = %q, want %q", props[propLastTimestamp], t4.Format(time.RFC3339))
	}
}

// openFindingIn returns the shape a counter-sourced open observation has: no
// destination, no process, nothing but the path to tell two violations of one
// policy apart.
func openFindingIn(namespace, podUID, path string, at time.Time) Finding {
	return Finding{
		PolicyName: "block-secrets",
		PolicyUID:  "policy-uid-1",
		Behavior:   "open",
		Target:     path,
		Result:     ResultFail,
		Message:    "monitor mode: open of " + path + " would have been denied by policy block-secrets",
		Pod: runtimeevent.PodIdentity{
			UID:       podUID,
			Namespace: namespace,
			Name:      "pod-" + podUID,
			Container: "app",
			NodeName:  "node-a",
		},
		Timestamp: at,
	}
}

func TestOpenFindingsSplitByPathAndRepeatsMerge(t *testing.T) {
	c := newRecordingClient(t)
	r, _ := newTestReporter(t, c, Options{NodeName: "node-a"})

	t1 := fixedTime
	t2 := fixedTime.Add(time.Minute)

	r.Report(openFindingIn("default", "pod-1", "/etc/hostname", t2))
	r.Report(openFindingIn("default", "pod-1", "/etc/resolv.conf", t1))
	r.Report(openFindingIn("default", "pod-1", "/etc/hostname", t1))

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	report := getReport(t, c, "default", "kyverno-runtime-pod-pod-1")
	if len(report.Results) != 2 {
		t.Fatalf("report holds %d results, want 2 (one per path)", len(report.Results))
	}

	byTarget := map[string]map[string]string{}
	for _, res := range report.Results {
		byTarget[res.Properties[propTarget]] = res.Properties
	}
	hostname, ok := byTarget["/etc/hostname"]
	if !ok {
		t.Fatalf("no result for /etc/hostname, got targets %v", byTarget)
	}
	if _, ok := byTarget["/etc/resolv.conf"]; !ok {
		t.Fatalf("no result for /etc/resolv.conf, got targets %v", byTarget)
	}
	if hostname[propCount] != "2" {
		t.Errorf("count for the repeated path = %q, want 2", hostname[propCount])
	}
	if hostname[propFirstTimestamp] != t1.Format(time.RFC3339) {
		t.Errorf("firstTimestamp = %q, want %q", hostname[propFirstTimestamp], t1.Format(time.RFC3339))
	}
	if hostname[propLastTimestamp] != t2.Format(time.RFC3339) {
		t.Errorf("lastTimestamp = %q, want %q", hostname[propLastTimestamp], t2.Format(time.RFC3339))
	}
}

func TestFlushCapsResultsAndAnnotatesTruncation(t *testing.T) {
	c := newRecordingClient(t)
	r, _ := newTestReporter(t, c, Options{NodeName: "node-a", MaxResultsPerReport: 2})

	r.Report(openFindingIn("default", "pod-1", "/etc/one", fixedTime.Add(1*time.Minute)))
	r.Report(openFindingIn("default", "pod-1", "/etc/two", fixedTime.Add(2*time.Minute)))
	r.Report(openFindingIn("default", "pod-1", "/etc/three", fixedTime.Add(3*time.Minute)))

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}

	report := getReport(t, c, "default", "kyverno-runtime-pod-pod-1")
	if len(report.Results) != 2 {
		t.Fatalf("report holds %d results, want 2 (capped)", len(report.Results))
	}
	if got := report.Annotations[AnnotationTruncatedResults]; got != "true" {
		t.Errorf("truncation annotation = %q, want \"true\"", got)
	}
	if report.Summary.Fail != 2 {
		t.Errorf("summary.Fail = %d, want 2 (kept results only)", report.Summary.Fail)
	}

	// The most recently seen findings are the ones kept.
	kept := map[string]bool{}
	for _, res := range report.Results {
		kept[res.Properties[propTarget]] = true
	}
	if !kept["/etc/three"] || !kept["/etc/two"] {
		t.Errorf("truncation dropped the newest findings, kept %v", kept)
	}
}

func TestFlushSkipsNoOpUpdate(t *testing.T) {
	c := newRecordingClient(t)
	r, m := newTestReporter(t, c, Options{NodeName: "node-a", MaxResultsPerReport: 1})

	r.Report(findingIn("default", "pod-1", fixedTime))
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("first flush: %v", err)
	}
	if c.creates != 1 || c.updates != 0 {
		t.Fatalf("after first flush: creates=%d updates=%d, want 1/0", c.creates, c.updates)
	}

	// Report at capacity with no new fingerprint: nothing worth an API write.
	r.Report(findingIn("default", "pod-1", fixedTime.Add(time.Minute)))
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if c.updates != 0 {
		t.Errorf("no-op flush issued %d updates, want 0", c.updates)
	}
	if got := testutil.ToFloat64(m.ReportWrites.WithLabelValues(writeSkipped)); got != 1 {
		t.Errorf("ReportWrites{skipped} = %v, want 1", got)
	}

	// An empty buffer does not even reach the API server.
	before := c.gets
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("empty flush: %v", err)
	}
	if c.gets != before {
		t.Errorf("empty flush performed %d gets, want 0", c.gets-before)
	}
}

func TestReportDropsFindingWithUnusableNamespace(t *testing.T) {
	c := newRecordingClient(t)
	r, m := newTestReporter(t, c, Options{NodeName: "node-a"})

	for _, ns := range []string{"", "Bearer sk-ant-leak", "UPPER", "has/slash"} {
		r.Report(findingIn(ns, "pod-1", fixedTime))
	}

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if reports := listReports(t, c); len(reports) != 0 {
		t.Fatalf("wrote %d reports for unusable namespaces, want 0", len(reports))
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues("reporter", "unattributed")); got != 4 {
		t.Errorf("EventsDropped = %v, want 4", got)
	}
}

func TestReportDropsFindingWithInvalidPodName(t *testing.T) {
	c := newRecordingClient(t)
	r, m := newTestReporter(t, c, Options{NodeName: "node-a"})

	for _, name := range []string{"", "UPPER", "has/slash", "trailing-"} {
		f := findingIn("default", "pod-1", fixedTime)
		f.Pod.Name = name
		r.Report(f)
	}

	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if reports := listReports(t, c); len(reports) != 0 {
		t.Fatalf("wrote %d reports for unusable pod names, want 0", len(reports))
	}
	if got := testutil.ToFloat64(m.EventsDropped.WithLabelValues("reporter", "unattributed")); got != 4 {
		t.Errorf("EventsDropped = %v, want 4", got)
	}
}

// TestReportAtHighVerbosityLogsEveryBehaviorWithoutPanicking exercises the
// per-event log line at the verbosity an operator would raise to stream
// events, across every behavior's summary shape.
func TestReportAtHighVerbosityLogsEveryBehaviorWithoutPanicking(t *testing.T) {
	c := newRecordingClient(t)
	log := testr.NewWithOptions(t, testr.Options{Verbosity: 4})
	r := New(c, log, nil, Options{NodeName: "node-a", Clock: func() time.Time { return fixedTime }})

	base := findingIn("default", "pod-1", fixedTime)
	base.Net = nil

	dns := base
	dns.Behavior = "dns"
	dns.DNS = &DNSSummary{QName: "example.com"}

	process := base
	process.Behavior = "exec"
	process.Process = &ProcessSummary{Comm: "cat", Argv: "cat /etc/hosts"}

	for _, f := range []Finding{findingIn("default", "pod-1", fixedTime), dns, process} {
		r.Report(f)
	}
}

func TestLongPodNamesProduceDistinctValidReportNames(t *testing.T) {
	if got := reportNameForPod("dns-client"); got != "kyverno-runtime-dns-client" {
		t.Errorf("reportNameForPod(dns-client) = %q, want kyverno-runtime-dns-client", got)
	}

	shared := strings.Repeat("a", 80)
	nameX := reportNameForPod(shared + "-x")
	nameY := reportNameForPod(shared + "-y")
	if nameX == nameY {
		t.Fatalf("pod names sharing a long prefix collided on report name %q", nameX)
	}
	for _, name := range []string{nameX, nameY} {
		if len(name) > 63 {
			t.Errorf("report name %q is %d chars, want <= 63", name, len(name))
		}
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
			t.Errorf("report name %q is not a valid object name: %v", name, errs[0])
		}
	}
	if again := reportNameForPod(shared + "-x"); again != nameX {
		t.Errorf("report name is not stable: %q then %q", nameX, again)
	}
}

func TestFlushRequeuesFindingsOnWriteError(t *testing.T) {
	c := newRecordingClient(t)
	c.failCreate = errors.New("apiserver unavailable")
	r, m := newTestReporter(t, c, Options{NodeName: "node-a"})

	r.Report(findingIn("default", "pod-1", fixedTime))

	if err := r.flush(context.Background()); err == nil {
		t.Fatal("flush returned nil after a create failure")
	}
	if got := testutil.ToFloat64(m.ReportWrites.WithLabelValues(writeError)); got != 1 {
		t.Errorf("ReportWrites{error} = %v, want 1", got)
	}

	// The finding survived the failure and is written by the next flush,
	// exactly once (no double counting).
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	report := getReport(t, c, "default", "kyverno-runtime-pod-pod-1")
	if len(report.Results) != 1 {
		t.Fatalf("report holds %d results after retry, want 1", len(report.Results))
	}
	if got := report.Results[0].Properties[propCount]; got != "1" {
		t.Errorf("count after retry = %q, want 1 (requeue must not double count)", got)
	}
}

func TestRunFlushesOnShutdown(t *testing.T) {
	c := newRecordingClient(t)
	// A long interval proves the write came from the shutdown flush, not a tick.
	r, _ := newTestReporter(t, c, Options{NodeName: "node-a", FlushInterval: time.Hour})

	r.Report(findingIn("default", "pod-1", fixedTime))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run returned %v, want nil on clean shutdown", err)
	}

	report := getReport(t, c, "default", "kyverno-runtime-pod-pod-1")
	if len(report.Results) != 1 {
		t.Errorf("shutdown flush wrote %d results, want 1", len(report.Results))
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	c := newRecordingClient(t)
	r := New(c, testLogger(t), nil, Options{})

	if r.opts.MaxResultsPerReport != DefaultMaxResultsPerReport {
		t.Errorf("MaxResultsPerReport = %d, want %d", r.opts.MaxResultsPerReport, DefaultMaxResultsPerReport)
	}
	if r.opts.FlushInterval != DefaultFlushInterval {
		t.Errorf("FlushInterval = %v, want %v", r.opts.FlushInterval, DefaultFlushInterval)
	}
	if r.opts.Clock == nil {
		t.Error("Clock was not defaulted")
	}
	if r.opts.NodeName != unknownNode {
		t.Errorf("NodeName = %q, want %q", r.opts.NodeName, unknownNode)
	}

	// Nil metrics must not panic anywhere on the hot path.
	r.Report(findingIn("default", "pod-1", fixedTime))
	if err := r.flush(context.Background()); err != nil {
		t.Fatalf("flush with nil metrics: %v", err)
	}
}
