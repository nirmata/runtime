// Package shadowai_test drives the whole userspace shadow-AI pipeline over the
// fixtures in this directory:
//
//	events.json -> collector.LoadEvents
//	            -> attribution.Index (cgroup -> pod)
//	            -> governed bit      (from aicontrols.json)
//	            -> ai.Classifier     (sets ev.AI)
//	            -> detect.Engine     (policy routing)
//	            -> reporter.Finding + inventory.Rollup
//
// Everything above the kernel is real code: the only substitutions are the
// event source (a JSON fixture instead of a BPF ring buffer, because the five
// kernel sources cannot be compiled on a host without clang and vmlinux.h) and
// the AIControls endpoint set (a fixture instead of a Service lookup; the
// resolver's own tests cover that path against a fake clientset).
//
// Run `go test ./test/samples/shadow-ai/ -update` to regenerate the goldens,
// then READ THE DIFF: these files are the specification of what the pipeline
// classifies and reports.
package shadowai_test

import (
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/attribution"
	"github.com/nirmata/kyverno-runtime/pkg/collector"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/detect"
	"github.com/nirmata/kyverno-runtime/pkg/detect/ai"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/inventory"
	"github.com/nirmata/kyverno-runtime/pkg/reporter"
	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

var update = flag.Bool("update", false, "regenerate the golden files")

// canaries are planted in fixtures/events.json. None of them may appear in a
// finding, an inventory entry, or any golden file: HTTPFacts redacts secret
// header values at construction and reporter.Finding has nowhere to put a body.
var canaries = []string{"Bearer sk-canary-XYZ", "sk-canary-XYZ", "canary-KEY-123", "CANARY-PROMPT"}

// fixedNow keeps inventory timestamps deterministic.
var fixedNow = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

// --- fixture shapes --------------------------------------------------------

type fixturePod struct {
	UID            string            `json:"uid"`
	Namespace      string            `json:"namespace"`
	Name           string            `json:"name"`
	Labels         map[string]string `json:"labels"`
	ServiceAccount string            `json:"serviceAccount"`
	Owner          *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"owner"`
	Containers []struct {
		Name     string `json:"name"`
		CgroupID uint64 `json:"cgroupID"`
	} `json:"containers"`
}

type fixtureAIControls struct {
	ProxyAddrs []string `json:"proxyAddrs"`
}

// classification is the golden shape for "what did the classifier decide".
type classification struct {
	Kind     string   `json:"kind"`
	Pod      string   `json:"pod"`
	Class    string   `json:"class,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Endpoint string   `json:"endpointKind,omitempty"`
	Model    string   `json:"model,omitempty"`
	Method   string   `json:"jsonrpcMethod,omitempty"`
	Trans    string   `json:"transport,omitempty"`
	Conf     int      `json:"confidence,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
	Governed *bool    `json:"governed,omitempty"`
	NotAI    bool     `json:"notAI,omitempty"`
}

// findingRow is the golden shape for an emitted finding, with the volatile
// fields (timestamps) dropped.
type findingRow struct {
	Policy      string   `json:"policy"`
	Severity    string   `json:"severity"`
	Result      string   `json:"result"`
	Message     string   `json:"message"`
	Pod         string   `json:"pod"`
	Class       string   `json:"class,omitempty"`
	Provider    string   `json:"provider,omitempty"`
	Endpoint    string   `json:"endpointKind,omitempty"`
	Confidence  int      `json:"confidence,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Governed    *bool    `json:"governed,omitempty"`
	DestHost    string   `json:"destHost,omitempty"`
	DestPort    uint16   `json:"destPort,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

// --- helpers ---------------------------------------------------------------

func loadJSON[T any](t *testing.T, name string) T {
	t.Helper()
	var out T
	b, err := os.ReadFile(filepath.Join("fixtures", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshalling fixture %s: %v", name, err)
	}
	return out
}

// seedAttribution builds the reverse index the collector stage needs, the same
// way podWatcher would from real pod events.
func seedAttribution(t *testing.T, pods []fixturePod) *attribution.Index {
	t.Helper()
	idx := attribution.NewIndex(logr.Discard())
	for _, p := range pods {
		for _, c := range p.Containers {
			id := runtimeevent.PodIdentity{
				UID:            p.UID,
				Namespace:      p.Namespace,
				Name:           p.Name,
				Labels:         p.Labels,
				Container:      c.Name,
				ServiceAccount: p.ServiceAccount,
			}
			if p.Owner != nil {
				id.OwnerKind, id.OwnerName = p.Owner.Kind, p.Owner.Name
			}
			idx.Put(c.CgroupID, id)
		}
	}
	return idx
}

// governedStage marks each flow governed or not from the fixture's proxy
// address set. It stands in for aicontrols.EndpointResolver, whose Service and
// EndpointSlice lookups are covered by its own tests; the semantics asserted
// here are the ones that reach a finding.
type governedStage struct{ proxies map[netip.Addr]struct{} }

func (g governedStage) Name() string { return "aicontrols-fixture" }

func (g governedStage) Process(ev *runtimeevent.Event) bool {
	if ev.Net == nil || !ev.Net.DestIP.IsValid() {
		return true // no destination to judge: governed stays unknown
	}
	_, ok := g.proxies[ev.Net.DestIP]
	ev.Net.Governed = &ok
	return true
}

// compilePolicies compiles every YAML under policies/ through the real
// compiler, which is also an assertion that the sample policies are valid.
func compilePolicies(t *testing.T) []*compiler.EvaluationResult {
	t.Helper()

	entries, err := os.ReadDir("policies")
	if err != nil {
		t.Fatalf("reading policies dir: %v", err)
	}
	c, err := compiler.NewCompiler(nil)
	if err != nil {
		t.Fatalf("NewCompiler: %v", err)
	}

	var out []*compiler.EvaluationResult
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("policies", e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var rp v1alpha1.RuntimePolicy
		if err := yaml.UnmarshalStrict(b, &rp); err != nil {
			t.Fatalf("%s does not deserialize into RuntimePolicy: %v", e.Name(), err)
		}
		// The API server assigns a UID; a manifest on disk has none. Every
		// consumer keys policies by UID, so without this the sample's five
		// policies would collapse into one entry.
		if rp.UID == "" {
			rp.UID = types.UID("uid-" + rp.Name)
		}
		compiled, err := c.Compile(rp)
		if err != nil {
			t.Fatalf("%s does not compile: %v", e.Name(), err)
		}
		res, err := compiled.Evaluate(t.Context())
		if err != nil {
			t.Fatalf("%s does not evaluate: %v", e.Name(), err)
		}
		if len(res.AI) == 0 {
			t.Errorf("%s compiled to no AI rules; the sample is meant to exercise the ai behavior", e.Name())
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		t.Fatal("no sample policies found under policies/")
	}
	return out
}

func assertGolden(t *testing.T, name string, got any) {
	t.Helper()

	want, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshalling %s: %v", name, err)
	}
	want = append(want, '\n')

	path := filepath.Join("expected", name)
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatalf("writing golden %s: %v", path, err)
		}
		t.Logf("updated %s", path)
		return
	}

	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden %s (run with -update to create it): %v", path, err)
	}
	if diff := cmp.Diff(string(have), string(want)); diff != "" {
		t.Errorf("%s is out of date (-golden +got):\n%s", name, diff)
	}
}

// --- the pipeline test -----------------------------------------------------

func TestPipeline(t *testing.T) {
	pods := loadJSON[[]fixturePod](t, "pods.json")
	acFixture := loadJSON[fixtureAIControls](t, "aicontrols.json")

	rawEvents, err := os.Open(filepath.Join("fixtures", "events.json"))
	if err != nil {
		t.Fatalf("opening events fixture: %v", err)
	}
	defer rawEvents.Close()
	evs, err := collector.LoadEvents(rawEvents)
	if err != nil {
		t.Fatalf("events.json does not load as []runtimeevent.Event: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("events.json produced no events")
	}

	proxies := map[netip.Addr]struct{}{}
	for _, a := range acFixture.ProxyAddrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			t.Fatalf("aicontrols.json proxy address %q: %v", a, err)
		}
		proxies[addr] = struct{}{}
	}

	idx := seedAttribution(t, pods)
	classifier := ai.NewClassifier(ai.DefaultCatalog())
	governed := governedStage{proxies: proxies}

	findings := &recordingFindings{}
	rollup := inventory.New(logr.Discard(), inventory.WithClock(func() time.Time { return fixedNow }))
	engine := detect.NewEngine(detect.Config{
		Findings:  findings,
		Inventory: rollup,
		Catalog:   classifier.Catalog(),
		// Strict: HandleEvent converts a panic into a logged error, so a
		// discarding logger would turn a nil dereference into a silent "no
		// finding". That is how the ev.Net bug in messageFor first hid here.
		Log: strictLogger(t),
	})

	for _, res := range compilePolicies(t) {
		if err := engine.RuntimePolicyEvent(res, events.EventTypeCreate); err != nil {
			t.Fatalf("tracking policy %s: %v", res.Name, err)
		}
	}

	// Drive the stages in the same order daemon.go wires them.
	classifications := make([]classification, 0, len(evs))
	attributed := 0
	for i := range evs {
		ev := evs[i]
		if !idx.Annotate(&ev) {
			// Unattributable events are dropped before any sink sees them.
			classifications = append(classifications, classification{
				Kind: string(ev.Kind), Pod: "<unattributed>",
			})
			continue
		}
		attributed++
		governed.Process(&ev)
		classifier.Process(&ev)
		classifications = append(classifications, classificationOf(ev))
		engine.HandleEvent(ev)
	}

	if attributed == 0 {
		t.Fatal("no fixture event attributed to a pod: check that pods.json cgroupIDs match events.json")
	}
	// A coverage floor, so a future change that silently stops classifying or
	// stops matching cannot leave this test green with empty goldens.
	if engine.Len() != 5 {
		t.Errorf("engine tracks %d policies, want the sample's 5", engine.Len())
	}
	if len(findings.findings) == 0 {
		t.Error("no findings produced from the sample: the monitor/enforce policies matched nothing")
	}
	if len(rollup.Snapshot()) == 0 {
		t.Error("no inventory entries produced from the sample: the discover policy matched nothing")
	}

	// --- goldens ---
	assertGolden(t, "classifications.golden.json", classifications)
	assertGolden(t, "findings.golden.json", findingRows(findings.findings))
	assertGolden(t, "inventory.golden.json", rollup.Snapshot())

	// --- the redaction assertion this whole sample exists for ---
	t.Run("no canary reaches a finding or the inventory", func(t *testing.T) {
		haystacks := map[string]string{
			"findings":        mustJSON(t, findingRows(findings.findings)),
			"inventory":       mustJSON(t, rollup.Snapshot()),
			"classifications": mustJSON(t, classifications),
		}
		for where, hay := range haystacks {
			for _, c := range canaries {
				if strings.Contains(hay, c) {
					t.Errorf("canary %q leaked into %s", c, where)
				}
			}
		}

		// Positive control: the canaries really are in the source fixture, so a
		// scan that finds nothing above is meaningful rather than vacuous.
		raw, err := os.ReadFile(filepath.Join("fixtures", "events.json"))
		if err != nil {
			t.Fatalf("reading events fixture: %v", err)
		}
		for _, c := range canaries {
			if !strings.Contains(string(raw), c) {
				t.Errorf("canary %q is not present in events.json; the leak scan proves nothing", c)
			}
		}
	})

	// Redaction must also hold on the event objects themselves.
	t.Run("secret header values are redacted at construction", func(t *testing.T) {
		var sawSecretHeader bool
		for i := range evs {
			ev := evs[i]
			if ev.HTTP == nil {
				continue
			}
			for name, value := range ev.HTTP.Headers() {
				switch name {
				case "authorization", "x-api-key":
					sawSecretHeader = true
					if value != runtimeevent.Redacted {
						t.Errorf("header %q = %q, want %q", name, value, runtimeevent.Redacted)
					}
				}
			}
		}
		if !sawSecretHeader {
			t.Error("no fixture event carried a secret header; the redaction assertion proves nothing")
		}
	})
}

// TestDiscoverModeProducesInventoryWithoutFindings pins the operational reason
// discover mode exists: per-event findings at discovery scale are unusable.
func TestDiscoverModeProducesInventoryWithoutFindings(t *testing.T) {
	pods := loadJSON[[]fixturePod](t, "pods.json")

	f, err := os.Open(filepath.Join("fixtures", "events.json"))
	if err != nil {
		t.Fatalf("opening events fixture: %v", err)
	}
	defer f.Close()
	evs, err := collector.LoadEvents(f)
	if err != nil {
		t.Fatalf("loading events: %v", err)
	}

	// Only the discover policy.
	var discover *compiler.EvaluationResult
	for _, res := range compilePolicies(t) {
		if res.Mode == compiler.ModeDiscover {
			discover = res
			break
		}
	}
	if discover == nil {
		t.Fatal("no discover-mode policy in policies/")
	}

	idx := seedAttribution(t, pods)
	classifier := ai.NewClassifier(ai.DefaultCatalog())
	findings := &recordingFindings{}
	rollup := inventory.New(logr.Discard(), inventory.WithClock(func() time.Time { return fixedNow }))
	engine := detect.NewEngine(detect.Config{
		Findings:  findings,
		Inventory: rollup,
		Catalog:   classifier.Catalog(),
		// Strict: HandleEvent converts a panic into a logged error, so a
		// discarding logger would turn a nil dereference into a silent "no
		// finding". That is how the ev.Net bug in messageFor first hid here.
		Log: strictLogger(t),
	})
	if err := engine.RuntimePolicyEvent(discover, events.EventTypeCreate); err != nil {
		t.Fatal(err)
	}

	for i := range evs {
		ev := evs[i]
		if !idx.Annotate(&ev) {
			continue
		}
		classifier.Process(&ev)
		engine.HandleEvent(ev)
	}

	if got := len(findings.findings); got != 0 {
		t.Errorf("discover mode emitted %d findings, want 0", got)
	}
	if got := len(rollup.Snapshot()); got == 0 {
		t.Error("discover mode recorded no inventory entries")
	}
}

// TestChainsawManifestsDeserialize checks the shadow-AI chainsaw fixtures
// against the Go types without needing a cluster. The chainsaw suite itself
// asserts what the API SERVER does with them (accept vs reject); this asserts
// that the ones expected to be accepted are at least well-formed, so a typo in a
// field name cannot masquerade as a successful rejection.
func TestChainsawManifestsDeserialize(t *testing.T) {
	dir := filepath.Join("..", "..", "chainsaw", "shadow-ai")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading chainsaw dir: %v", err)
	}

	var seenValid, seenInvalid int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") || name == "chainsaw-test.yaml" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}

		switch {
		case strings.HasPrefix(name, "valid-aiinventory"):
			var inv v1alpha1.AIInventory
			if err := yaml.UnmarshalStrict(b, &inv); err != nil {
				t.Errorf("%s does not deserialize into AIInventory: %v", name, err)
				continue
			}
			seenValid++
		case strings.HasPrefix(name, "valid-"):
			var rp v1alpha1.RuntimePolicy
			if err := yaml.UnmarshalStrict(b, &rp); err != nil {
				t.Errorf("%s does not deserialize into RuntimePolicy: %v", name, err)
				continue
			}
			if len(rp.Spec.Behaviors) == 0 {
				t.Errorf("%s has no behaviors; it would assert nothing", name)
			}
			seenValid++
		case strings.HasPrefix(name, "bad-"):
			// These are rejected by the API server's schema (enums, bounds, the
			// exactly-one XValidation), none of which Go types express — so they
			// must still be structurally parseable, or chainsaw would be
			// asserting a YAML error rather than an admission error.
			var rp v1alpha1.RuntimePolicy
			if err := yaml.Unmarshal(b, &rp); err != nil {
				t.Errorf("%s is not parseable YAML, so the chainsaw case would pass for the wrong reason: %v", name, err)
				continue
			}
			seenInvalid++
		}
	}

	if seenValid == 0 || seenInvalid == 0 {
		t.Errorf("expected both valid and invalid chainsaw manifests, got valid=%d invalid=%d", seenValid, seenInvalid)
	}
}

// --- small helpers ---------------------------------------------------------

type recordingFindings struct{ findings []reporter.Finding }

func (r *recordingFindings) Report(f reporter.Finding) { r.findings = append(r.findings, f) }

// failOnErrorSink fails the test on any logged error. The engine's Sink contract
// forbids panicking outward, so panics arrive as logged errors: with a
// discarding logger a nil dereference is indistinguishable from "this event
// simply produced no finding".
type failOnErrorSink struct{ t *testing.T }

func (s failOnErrorSink) Init(logr.RuntimeInfo) {}

func (s failOnErrorSink) Enabled(int) bool { return true }

func (s failOnErrorSink) Info(int, string, ...any) {}

func (s failOnErrorSink) Error(err error, msg string, kv ...any) {
	s.t.Errorf("pipeline logged an error (a swallowed panic looks like this): %v: %s %v", err, msg, kv)
}

func (s failOnErrorSink) WithValues(...any) logr.LogSink { return s }

func (s failOnErrorSink) WithName(string) logr.LogSink { return s }

func strictLogger(t *testing.T) logr.Logger {
	t.Helper()
	return logr.New(failOnErrorSink{t: t})
}

func classificationOf(ev runtimeevent.Event) classification {
	c := classification{Kind: string(ev.Kind), Pod: ev.Pod.Namespace + "/" + ev.Pod.Name}
	if ev.Net != nil {
		c.Governed = ev.Net.Governed
	}
	if ev.AI == nil {
		c.NotAI = true
		return c
	}
	c.Class = string(ev.AI.Class)
	c.Provider = ev.AI.Provider
	c.Endpoint = ev.AI.EndpointKind
	c.Model = ev.AI.Model
	c.Method = ev.AI.JSONRPCMethod
	c.Trans = ev.AI.Transport
	c.Conf = ev.AI.Confidence
	c.Evidence = ev.AI.Evidence
	return c
}

func findingRows(fs []reporter.Finding) []findingRow {
	rows := make([]findingRow, 0, len(fs))
	for _, f := range fs {
		row := findingRow{
			Policy:      f.PolicyName,
			Severity:    f.Severity,
			Result:      f.Result,
			Message:     f.Message,
			Pod:         f.Pod.Namespace + "/" + f.Pod.Name,
			Fingerprint: f.Fingerprint(),
		}
		if f.AI != nil {
			row.Class = f.AI.Class
			row.Provider = f.AI.Provider
			row.Endpoint = f.AI.EndpointKind
			row.Confidence = f.AI.Confidence
			row.Evidence = f.AI.Evidence
			row.Governed = f.AI.Governed
		}
		if f.Net != nil {
			row.DestHost = f.Net.DestHost
			row.DestPort = f.Net.DestPort
		}
		rows = append(rows, row)
	}
	// Stable order: findings are produced per event per policy, and map
	// iteration over tracked policies is not ordered.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Pod != rows[j].Pod {
			return rows[i].Pod < rows[j].Pod
		}
		if rows[i].Policy != rows[j].Policy {
			return rows[i].Policy < rows[j].Policy
		}
		if rows[i].Message != rows[j].Message {
			return rows[i].Message < rows[j].Message
		}
		return rows[i].Fingerprint < rows[j].Fingerprint
	})
	return rows
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(b)
}
