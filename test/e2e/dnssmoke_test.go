package e2e_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/bpf/dnsquery"
	"github.com/nirmata/runtime/pkg/containers"
	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/go-logr/logr"
)

// TestDNSQueryMapsRoundTrip proves the loaded maps are usable from Go through
// the same calls dnsmgr makes. Verifier acceptance is TestBPFVerify's job.
func TestDNSQueryMapsRoundTrip(t *testing.T) {
	requireBPFCapableHost(t)

	obs, err := dnsquery.New()
	if err != nil {
		// %+v renders *ebpf.VerifierError's full log.
		t.Fatalf("loading dnsquery objects: %+v", err)
	}
	defer func() { _ = obs.Close() }()

	if err := obs.AddCgids([]uint64{4242, 4243}); err != nil {
		t.Fatalf("admitting cgids: %v", err)
	}
	// Revoking twice must succeed: pod deletion and policy deletion can both
	// revoke the same cgroup.
	if err := obs.DeleteCgids([]uint64{4242, 4243}); err != nil {
		t.Fatalf("revoking cgids: %v", err)
	}
	if err := obs.DeleteCgids([]uint64{4242}); err != nil {
		t.Fatalf("revoking an absent cgid: %v", err)
	}

	stats, err := obs.ReadStats()
	if err != nil {
		t.Fatalf("reading loss counters: %v", err)
	}
	for i, v := range stats {
		if v != 0 {
			t.Errorf("loss counter %s = %d on a fresh object, want 0", dnsquery.StatNames[i], v)
		}
	}
}

// TestDNSQueryObservesARealQuery is the end-to-end assertion for the kernel
// path: attach to this process's own cgroup, admit it, send a real DNS question,
// and require the decoded question name to come back out of the ring buffer.
//
// Nothing needs to answer the query. cgroup_skb/egress runs on the send path,
// so the observation happens whether or not a resolver exists.
func TestDNSQueryObservesARealQuery(t *testing.T) {
	requireBPFCapableHost(t)

	obs, err := dnsquery.New()
	if err != nil {
		t.Fatalf("loading dnsquery objects: %+v", err)
	}
	defer func() { _ = obs.Close() }()

	self, err := containers.ResolveCgroupByPID("/proc", uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("resolving this process's cgroup: %v", err)
	}

	l, err := obs.Attach(self.Path)
	if err != nil {
		t.Fatalf("attaching to %s: %v", self.Path, err)
	}
	defer func() { _ = l.Close() }()

	if err := obs.AddCgids([]uint64{self.ID}); err != nil {
		t.Fatalf("admitting cgid %d: %v", self.ID, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	events := make(chan runtimeevent.Event, 16)
	srcErr := make(chan error, 1)
	src := dnsquery.NewSource(logr.Discard(), obs)
	go func() { srcErr <- src.Run(ctx, events) }()

	// The reader has to be draining before the query, or the record is produced
	// into a ring buffer nobody has opened yet.
	time.Sleep(500 * time.Millisecond)

	const want = "api.openai.com"
	if err := sendDNSQuery(want); err != nil {
		t.Fatalf("sending the query: %v", err)
	}

	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind != runtimeevent.KindDNS {
				t.Errorf("Kind = %q, want %q", ev.Kind, runtimeevent.KindDNS)
			}
			if ev.DNS == nil {
				t.Fatal("event carries no DNS facts")
			}
			if ev.DNS.QName != want {
				// Another query from this cgroup can arrive first; keep looking.
				t.Logf("ignoring unrelated question %q", ev.DNS.QName)
				continue
			}
			if ev.CgroupID != self.ID {
				t.Errorf("CgroupID = %d, want %d: attribution would resolve the wrong pod", ev.CgroupID, self.ID)
			}
			if ev.Time.IsZero() {
				t.Error("Time is zero: the source must stamp the record")
			}
			if ev.Count != 1 {
				t.Errorf("Count = %d, want 1: a ring buffer record is one query, not an aggregate", ev.Count)
			}
			return
		case err := <-srcErr:
			t.Fatalf("source returned before the query was observed: %v", err)
		case <-deadline:
			t.Fatalf("no event for %q within the deadline", want)
		}
	}
}

// TestDNSQueryIgnoresUnadmittedCgroups is the other half of the gate: a query
// from a cgroup that no policy selected must produce nothing at all, because an
// event that is never produced cannot be dropped, decoded or reported.
func TestDNSQueryIgnoresUnadmittedCgroups(t *testing.T) {
	requireBPFCapableHost(t)

	obs, err := dnsquery.New()
	if err != nil {
		t.Fatalf("loading dnsquery objects: %+v", err)
	}
	defer func() { _ = obs.Close() }()

	self, err := containers.ResolveCgroupByPID("/proc", uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("resolving this process's cgroup: %v", err)
	}

	l, err := obs.Attach(self.Path)
	if err != nil {
		t.Fatalf("attaching to %s: %v", self.Path, err)
	}
	defer func() { _ = l.Close() }()

	// Attached but deliberately not admitted.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events := make(chan runtimeevent.Event, 16)
	src := dnsquery.NewSource(logr.Discard(), obs)
	go func() { _ = src.Run(ctx, events) }()
	time.Sleep(500 * time.Millisecond)

	if err := sendDNSQuery("unadmitted.example.com"); err != nil {
		t.Fatalf("sending the query: %v", err)
	}

	select {
	case ev := <-events:
		name := ""
		if ev.DNS != nil {
			name = ev.DNS.QName
		}
		t.Fatalf("observed %q from a cgroup that was never admitted to the gate", name)
	case <-time.After(3 * time.Second):
	}
}

// sendDNSQuery writes one A-record question to the loopback resolver port. It
// does not wait for an answer and treats a refusal as success: the point is that
// the datagram left the socket.
func sendDNSQuery(name string) error {
	c, err := net.Dial("udp", "127.0.0.1:53")
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if _, err := c.Write(dnsQuestion(name)); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// dnsQuestion builds a minimal wire-format A query: a 12-byte header with one
// question, then the label sequence, then qtype and qclass.
func dnsQuestion(name string) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, 0x1234) // id
	b = binary.BigEndian.AppendUint16(b, 0x0100) // recursion desired, QR clear
	b = binary.BigEndian.AppendUint16(b, 1)      // qdcount
	b = binary.BigEndian.AppendUint16(b, 0)      // ancount
	b = binary.BigEndian.AppendUint16(b, 0)      // nscount
	b = binary.BigEndian.AppendUint16(b, 0)      // arcount

	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)                        // root label
	b = binary.BigEndian.AppendUint16(b, 1) // qtype A
	b = binary.BigEndian.AppendUint16(b, 1) // qclass IN
	return b
}
