package pushsink

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nirmata/runtime/pkg/proto/finding"
	"github.com/nirmata/runtime/pkg/reporter"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SourceName is the source label of every drop this sink counts.
const SourceName = "pushsink"

// Reasons a finding never reached the collector.
const (
	ReasonQueueFull  = "queue_full"
	ReasonSendFailed = "send_failed"
)

// DefaultQueueSize is how many findings may await transmission. The queue is
// memory on a privileged DaemonSet pod, so it is bounded and the overflow is
// counted rather than allowed to grow with a collector that stops reading.
const DefaultQueueSize = 4096

const (
	// A broken stream waits before reopening, doubling up to the cap. A
	// collector that is gone rather than restarting is the common case, and a
	// fleet of daemons retrying it every few seconds is both connection churn
	// and one error log per node per interval, forever.
	minRetryBackoff = 5 * time.Second
	maxRetryBackoff = time.Minute
	// defaultShutdownGrace bounds everything the stream does after the daemon's
	// context is cancelled: the final drain, an in-flight send, and the close.
	defaultShutdownGrace = 5 * time.Second
)

// Options configures a GRPCSink. Target and all three TLS paths are required:
// there is no value of this struct that transmits a finding in the clear.
type Options struct {
	// Target is the collector's address, as accepted by grpc.NewClient.
	Target string
	// CAFile verifies the collector. CertFile and KeyFile are this daemon's
	// client certificate.
	CAFile   string
	CertFile string
	KeyFile  string
	// QueueSize bounds the send queue (default DefaultQueueSize).
	QueueSize int
	// LossFunc counts findings that never reached the collector, by reason.
	// May be nil.
	LossFunc func(reason string, delta uint64)
}

// GRPCSink streams findings to a collector over a client-streaming RPC. It is
// a monitor.FindingSink: Report never blocks the event path, and everything it
// puts on the wire has been through reporter.Redact.
//
// The daemon is the client. Nothing here listens, so a node running this sink
// opens no port.
type GRPCSink struct {
	log           logr.Logger
	opts          Options
	creds         credentials.TransportCredentials
	queue         chan *finding.Finding
	shutdownGrace time.Duration

	// dropMu makes the drop-oldest overflow path atomic: it is a receive
	// followed by a send, and two producers interleaving them can drop two
	// findings to make room for one.
	dropMu sync.Mutex
}

// New builds a sink for opts. It fails rather than starting a daemon whose
// findings would silently go nowhere: an unreadable certificate is a
// configuration error, not something to discover on the first violation.
func New(log logr.Logger, opts Options) (*GRPCSink, error) {
	if opts.Target == "" {
		return nil, fmt.Errorf("push sink: no target")
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultQueueSize
	}

	creds, err := loadCredentials(opts)
	if err != nil {
		return nil, err
	}

	return &GRPCSink{
		log:           log,
		opts:          opts,
		creds:         creds,
		queue:         make(chan *finding.Finding, opts.QueueSize),
		shutdownGrace: defaultShutdownGrace,
	}, nil
}

// Report queues f for transmission. It never blocks: when the queue is full
// the oldest finding is dropped and counted, so a collector that stops reading
// costs the newest observations rather than the event path.
//
// Redaction happens here rather than at send time: what the queue holds is
// already scrubbed and bounded, so raw argv never sits in daemon memory
// waiting for a collector to come back.
func (s *GRPCSink) Report(f reporter.Finding) {
	msg := toProto(reporter.Redact(f))

	select {
	case s.queue <- msg:
		return
	default:
	}

	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	select {
	case s.queue <- msg:
		return
	default:
	}
	select {
	case <-s.queue:
		s.lost(ReasonQueueFull, 1)
	default:
	}
	select {
	case s.queue <- msg:
	default:
		s.lost(ReasonQueueFull, 1)
	}
}

// Run streams queued findings until ctx is done, reopening the stream after a
// failure. It returns nil on clean shutdown.
func (s *GRPCSink) Run(ctx context.Context) error {
	conn, err := grpc.NewClient(s.opts.Target, grpc.WithTransportCredentials(s.creds))
	if err != nil {
		return fmt.Errorf("push sink: connecting to %s: %w", s.opts.Target, err)
	}
	defer func() { _ = conn.Close() }()

	client := finding.NewFindingServiceClient(conn)
	s.log.V(2).Info("push sink started", "target", s.opts.Target, "queueSize", s.opts.QueueSize)

	backoff := minRetryBackoff
	for {
		opened, err := s.stream(ctx, client)
		if ctx.Err() != nil {
			s.log.V(2).Info("push sink stopped")
			return nil
		}
		if opened {
			backoff = minRetryBackoff
		}
		s.log.V(0).Error(err, "push stream failed, reopening", "target", s.opts.Target, "retryIn", backoff)
		select {
		case <-ctx.Done():
			s.log.V(2).Info("push sink stopped")
			return nil
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxRetryBackoff)
	}
}

// stream opens one client stream and feeds it until ctx is done or a send
// fails. A cancelled ctx closes the stream cleanly after one final drain, so
// findings observed just before shutdown still reach the collector.
//
// opened reports whether the stream was established, which is what separates a
// collector that is restarting from one that was never there: only the former
// earns a fresh backoff.
func (s *GRPCSink) stream(ctx context.Context, client finding.FindingServiceClient) (opened bool, err error) {
	// The stream outlives ctx by the shutdown drain, so it runs on its own
	// cancellation rather than on the daemon's.
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()

	// Send blocks while the flow control window is full, and a collector that
	// accepts a stream and stops reading it holds the window shut. The stream
	// is what that send waits on, so the deadline is armed here rather than in
	// the shutdown branch below: a goroutine blocked in Send never reaches it,
	// and the daemon would hang until the kubelet killed the pod.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
			return
		}
		select {
		case <-time.After(s.shutdownGrace):
			cancel()
		case <-done:
		}
	}()

	st, err := client.Report(streamCtx)
	if err != nil {
		return false, fmt.Errorf("push sink: opening stream to %s: %w", s.opts.Target, err)
	}

	for {
		select {
		case <-ctx.Done():
			s.drain(st)
			ack, closeErr := st.CloseAndRecv()
			if closeErr != nil {
				return true, fmt.Errorf("push sink: closing stream: %w", closeErr)
			}
			s.log.V(2).Info("push stream closed", "accepted", ack.GetAccepted())
			return true, nil
		case msg := <-s.queue:
			if err := st.Send(msg); err != nil {
				s.lost(ReasonSendFailed, 1)
				return true, fmt.Errorf("push sink: sending finding: %w", err)
			}
		}
	}
}

// drain sends what is already queued, counting whatever the stream refuses.
func (s *GRPCSink) drain(st grpc.ClientStreamingClient[finding.Finding, finding.Ack]) {
	for {
		select {
		case msg := <-s.queue:
			if err := st.Send(msg); err != nil {
				s.lost(ReasonSendFailed, uint64(len(s.queue))+1)
				return
			}
		default:
			return
		}
	}
}

func (s *GRPCSink) lost(reason string, delta uint64) {
	if s.opts.LossFunc == nil {
		return
	}
	s.opts.LossFunc(reason, delta)
}

// toProto renders a redacted finding on the wire. Every field of the message
// is filled from one here: a finding shape the collector cannot read is a
// silent monitoring gap on the receiving side.
func toProto(f reporter.Finding) *finding.Finding {
	msg := &finding.Finding{
		PolicyName: f.PolicyName,
		PolicyUid:  f.PolicyUID,
		Behavior:   f.Behavior,
		Target:     f.Target,
		Result:     f.Result,
		Enforced:   f.Enforced,
		Message:    f.Message,
		Pod: &finding.Pod{
			Uid:            f.Pod.UID,
			Namespace:      f.Pod.Namespace,
			Name:           f.Pod.Name,
			Container:      f.Pod.Container,
			ContainerId:    f.Pod.ContainerID,
			OwnerKind:      f.Pod.OwnerKind,
			OwnerName:      f.Pod.OwnerName,
			NodeName:       f.Pod.NodeName,
			ServiceAccount: f.Pod.ServiceAccount,
		},
	}
	if !f.Timestamp.IsZero() {
		msg.Timestamp = timestamppb.New(f.Timestamp)
	}
	if f.Net != nil {
		msg.Net = &finding.Net{DestIp: f.Net.DestIP, DestHost: f.Net.DestHost}
	}
	if f.DNS != nil {
		msg.Dns = &finding.Dns{Qname: f.DNS.QName}
	}
	if f.Process != nil {
		msg.Process = &finding.Process{Comm: f.Process.Comm, Argv: f.Process.Argv}
	}
	return msg
}
