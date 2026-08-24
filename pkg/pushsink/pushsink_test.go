package pushsink

import (
	"sync"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/proto/finding"
	"github.com/nirmata/runtime/pkg/reporter"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var fixedTime = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

// lossRecord counts what a sink reported as lost, by reason.
type lossRecord map[string]uint64

func (l lossRecord) record(reason string, delta uint64) { l[reason] += delta }

// newTestSink builds a sink with the queue depth the test needs and no
// transport: every assertion below stops at the queue.
func newTestSink(t *testing.T, queueSize int, loss lossRecord) *GRPCSink {
	t.Helper()
	return &GRPCSink{
		log:   logr.Discard(),
		opts:  Options{Target: "collector.example:443", QueueSize: queueSize, LossFunc: loss.record},
		queue: make(chan *finding.Finding, queueSize),
	}
}

func findingNamed(name string) reporter.Finding {
	return reporter.Finding{
		PolicyName: name,
		Behavior:   "exec",
		Target:     "/usr/bin/curl",
		Result:     reporter.ResultFail,
		Pod:        runtimeevent.PodIdentity{UID: "pod-uid", Namespace: "default", Name: "pod-1"},
		Timestamp:  fixedTime,
	}
}

func TestReportRedactsBeforeQueueing(t *testing.T) {
	loss := lossRecord{}
	s := newTestSink(t, 4, loss)

	f := findingNamed("p")
	f.Message = "exec carrying sk-ant-api03-aaaabbbbccccdddd"
	f.Process = &reporter.ProcessSummary{Comm: "curl", Argv: "curl -H Bearer sk-live-9f8e7d6c5b4a3210"}
	s.Report(f)

	got := <-s.queue
	if want := "exec carrying " + reporter.Redacted; got.GetMessage() != want {
		t.Errorf("queued message = %q, want %q", got.GetMessage(), want)
	}
	if want := "curl -H " + reporter.Redacted; got.GetProcess().GetArgv() != want {
		t.Errorf("queued argv = %q, want %q", got.GetProcess().GetArgv(), want)
	}
	if len(loss) != 0 {
		t.Errorf("loss recorded on a healthy queue: %v", loss)
	}
}

// A collector that stops reading costs the oldest observations, never the
// event path: Report keeps accepting and counts what it displaced.
func TestReportDropsOldestWhenTheQueueIsFull(t *testing.T) {
	loss := lossRecord{}
	s := newTestSink(t, 2, loss)

	for _, name := range []string{"first", "second", "third"} {
		s.Report(findingNamed(name))
	}

	var queued []string
	for len(s.queue) > 0 {
		queued = append(queued, (<-s.queue).GetPolicyName())
	}
	if diff := cmp.Diff([]string{"second", "third"}, queued); diff != "" {
		t.Errorf("queue holds the wrong findings (-want +got):\n%s", diff)
	}
	if got := loss[ReasonQueueFull]; got != 1 {
		t.Errorf("%s = %d, want 1", ReasonQueueFull, got)
	}
}

// A consumer racing the drop-oldest path can free a slot between a
// producer's failed fast-path send and its dropMu acquisition. Report must
// notice the free slot rather than evicting a finding that no longer needs
// evicting.
func TestReportDoesNotEvictWhenTheConsumerMadeRoom(t *testing.T) {
	for i := 0; i < 200; i++ {
		loss := lossRecord{}
		s := newTestSink(t, 2, loss)
		s.Report(findingNamed("A"))
		s.Report(findingNamed("B"))

		s.dropMu.Lock()
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.Report(findingNamed("C"))
		}()

		time.Sleep(time.Millisecond)
		<-s.queue // stands in for the stream consumer freeing a slot
		s.dropMu.Unlock()
		<-done

		if got := loss[ReasonQueueFull]; got != 0 {
			t.Fatalf("iteration %d: %s = %d, want 0", i, ReasonQueueFull, got)
		}
		var queued []string
		for len(s.queue) > 0 {
			queued = append(queued, (<-s.queue).GetPolicyName())
		}
		if diff := cmp.Diff([]string{"B", "C"}, queued); diff != "" {
			t.Fatalf("iteration %d: queue holds the wrong findings (-want +got):\n%s", i, diff)
		}
	}
}

// Every finding Report accepts must be accounted for: delivered to the
// queue, still sitting in it, or counted as lost. None may vanish.
func TestReportAccountsForEveryFindingUnderConcurrency(t *testing.T) {
	const (
		producers   = 8
		perProducer = 500
		total       = producers * perProducer
		queueSize   = 16
	)

	var mu sync.Mutex
	loss := lossRecord{}
	s := newTestSink(t, queueSize, loss)
	s.opts.LossFunc = func(reason string, delta uint64) {
		mu.Lock()
		defer mu.Unlock()
		loss[reason] += delta
	}

	drained := 0
	drainDone := make(chan struct{})
	stopDraining := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			select {
			case <-s.queue:
				drained++
			case <-stopDraining:
				for {
					select {
					case <-s.queue:
						drained++
					default:
						return
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(producers)
	for p := 0; p < producers; p++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				s.Report(findingNamed("x"))
			}
		}()
	}
	wg.Wait()
	close(stopDraining)
	<-drainDone

	mu.Lock()
	lost := loss[ReasonQueueFull]
	mu.Unlock()
	if got := drained + len(s.queue) + int(lost); got != total {
		t.Errorf("drained(%d) + queued(%d) + lost(%d) = %d, want %d", drained, len(s.queue), lost, got, total)
	}
}

func TestToProtoCarriesEveryFindingField(t *testing.T) {
	f := reporter.Finding{
		PolicyName: "block-egress",
		PolicyUID:  "policy-uid",
		Behavior:   "network",
		Target:     "api.example.com",
		Result:     reporter.ResultFail,
		Enforced:   true,
		Message:    "enforced: egress to api.example.com was denied by policy block-egress",
		Pod: runtimeevent.PodIdentity{
			UID:            "pod-uid",
			Namespace:      "default",
			Name:           "pod-1",
			Labels:         map[string]string{"team": "payments"},
			Container:      "app",
			ContainerID:    "containerd://abc",
			OwnerKind:      "Deployment",
			OwnerName:      "app",
			NodeName:       "node-a",
			ServiceAccount: "sa",
		},
		Net:       &reporter.NetSummary{DestIP: "1.2.3.4", DestHost: "api.example.com"},
		DNS:       &reporter.DNSSummary{QName: "api.example.com"},
		Process:   &reporter.ProcessSummary{Comm: "curl", Argv: "curl https://api.example.com"},
		Timestamp: fixedTime,
	}

	want := &finding.Finding{
		PolicyName: "block-egress",
		PolicyUid:  "policy-uid",
		Behavior:   "network",
		Target:     "api.example.com",
		Result:     reporter.ResultFail,
		Enforced:   true,
		Message:    "enforced: egress to api.example.com was denied by policy block-egress",
		Pod: &finding.Pod{
			Uid:            "pod-uid",
			Namespace:      "default",
			Name:           "pod-1",
			Container:      "app",
			ContainerId:    "containerd://abc",
			OwnerKind:      "Deployment",
			OwnerName:      "app",
			NodeName:       "node-a",
			ServiceAccount: "sa",
		},
		Net:       &finding.Net{DestIp: "1.2.3.4", DestHost: "api.example.com"},
		Dns:       &finding.Dns{Qname: "api.example.com"},
		Process:   &finding.Process{Comm: "curl", Argv: "curl https://api.example.com"},
		Timestamp: timestamppb.New(fixedTime),
	}

	if diff := cmp.Diff(want, toProto(f), protocmp.Transform()); diff != "" {
		t.Errorf("toProto (-want +got):\n%s", diff)
	}
}

// A finding whose summaries are absent must not put empty ones on the wire: a
// receiver reads presence as "this finding had a process", not as a zero value.
func TestToProtoOmitsAbsentSummaries(t *testing.T) {
	msg := toProto(findingNamed("p"))
	if msg.GetNet() != nil {
		t.Errorf("net summary present on a finding without one: %v", msg.GetNet())
	}
	if msg.GetDns() != nil {
		t.Errorf("dns summary present on a finding without one: %v", msg.GetDns())
	}
	if msg.GetProcess() != nil {
		t.Errorf("process summary present on a finding without one: %v", msg.GetProcess())
	}

	f := findingNamed("p")
	f.Timestamp = time.Time{}
	if ts := toProto(f).GetTimestamp(); ts != nil {
		t.Errorf("timestamp present on a finding without one: %v", ts)
	}
}
