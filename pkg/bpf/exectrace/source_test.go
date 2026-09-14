package exectrace

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nirmata/runtime/pkg/runtimeevent"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-logr/logr"
)

type fakeRingReader struct {
	err    error
	closed chan struct{}
	once   sync.Once
}

func newFakeRingReader(err error) *fakeRingReader {
	return &fakeRingReader{err: err, closed: make(chan struct{})}
}

func (r *fakeRingReader) Read() (ringbuf.Record, error) {
	if r.err != nil {
		return ringbuf.Record{}, r.err
	}
	<-r.closed
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *fakeRingReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

// TestSourceRunReopensReaderBeforeAnnouncingReady prevents a failed reader from
// being advertised as recovered without a usable replacement.
func TestSourceRunReopensReaderBeforeAnnouncingReady(t *testing.T) {
	readers := []ringReader{
		newFakeRingReader(errors.New("reader failed")),
		newFakeRingReader(nil),
	}
	opened := 0
	s := &Source{
		log:          logr.Discard(),
		statInterval: time.Hour,
		clock:        time.Now,
		newReader: func() (ringReader, error) {
			r := readers[opened]
			opened++
			return r, nil
		},
	}
	ready := make(chan struct{}, 2)
	ctx := runtimeevent.WithSourceReady(context.Background(), func() { ready <- struct{}{} })
	if err := s.Run(ctx, make(chan runtimeevent.Event)); err == nil {
		t.Fatal("first Run returned nil, want reader error")
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("first reader did not announce ready")
	}

	secondCtx, cancel := context.WithCancel(runtimeevent.WithSourceReady(context.Background(), func() { ready <- struct{}{} }))
	done := make(chan error, 1)
	go func() { done <- s.Run(secondCtx, make(chan runtimeevent.Event)) }()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("replacement reader did not announce ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("second Run = %v, want nil after cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Run did not return after cancellation")
	}
	if opened != 2 {
		t.Errorf("opened readers = %d, want 2", opened)
	}
}

// TestSourceRunDoesNotAnnounceReadyWhenReaderCannotOpen keeps an unsuccessful
// retry from clearing a source failure.
func TestSourceRunDoesNotAnnounceReadyWhenReaderCannotOpen(t *testing.T) {
	s := &Source{
		newReader: func() (ringReader, error) {
			return nil, errors.New("cannot open reader")
		},
	}
	ready := make(chan struct{}, 1)
	ctx := runtimeevent.WithSourceReady(context.Background(), func() { ready <- struct{}{} })
	if err := s.Run(ctx, make(chan runtimeevent.Event)); err == nil {
		t.Fatal("Run returned nil, want reader-open error")
	}
	select {
	case <-ready:
		t.Error("reader-open failure announced readiness")
	default:
	}
}

// TestSourceCloseSerializesReaderPublication keeps concurrent teardown from
// missing a reader opened by a source run or allowing one to open afterward.
func TestSourceCloseSerializesReaderPublication(t *testing.T) {
	for _, timing := range []string{"before run", "during reader creation", "while reading"} {
		t.Run(timing, func(t *testing.T) {
			rd := newFakeRingReader(nil)
			creating, release := make(chan struct{}), make(chan struct{})
			ready := make(chan struct{}, 1)
			s := &Source{
				log: logr.Discard(), statInterval: time.Hour, clock: time.Now,
				newReader: func() (ringReader, error) {
					close(creating)
					<-release
					return rd, nil
				},
			}
			if timing == "before run" {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				close(release)
			}
			ctx, cancel := context.WithCancel(runtimeevent.WithSourceReady(context.Background(), func() { ready <- struct{}{} }))
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx, make(chan runtimeevent.Event)) }()

			if timing != "before run" {
				<-creating
				if timing == "while reading" {
					close(release)
					<-ready
				}
				started, closed := make(chan struct{}), make(chan error, 2)
				go func() { close(started); closed <- s.Close() }()
				<-started
				go func() { closed <- s.Close() }()
				if timing == "during reader creation" {
					close(release)
				}
				for range 2 {
					if err := <-closed; err != nil {
						t.Errorf("Close = %v", err)
					}
				}
			}
			select {
			case err := <-done:
				if timing == "before run" {
					if !errors.Is(err, os.ErrClosed) {
						t.Errorf("Run = %v, want a closed source error", err)
					}
					select {
					case <-creating:
						t.Error("a closed source opened a reader")
					default:
					}
				} else if err != nil {
					t.Errorf("Run = %v, want nil after Close", err)
				}
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Error("Run did not return after Close")
			}
		})
	}
}
