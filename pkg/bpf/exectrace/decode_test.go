package exectrace

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/pkg/runtimeevent"

	"github.com/google/go-cmp/cmp"
)

// execRecord builds a kernel record byte-for-byte the way _cprog/exec.bpf.c
// writes it. Offsets are spelled out numerically so a layout change breaks the
// fixture instead of silently following the decoder.
type execRecord struct {
	cgroupID uint64
	pid      uint32
	comm     []byte
	filename []byte
	argv     [][]byte
	// argvLen, when nonzero, overrides the slot count written to the record.
	argvLen uint16
	pad     int
}

func (r execRecord) bytes() []byte {
	b := make([]byte, 1310+r.pad)
	binary.LittleEndian.PutUint64(b[0:8], r.cgroupID)
	binary.LittleEndian.PutUint32(b[8:12], r.pid)
	copy(b[12:28], r.comm)
	n := uint16(len(r.argv))
	if r.argvLen != 0 {
		n = r.argvLen
	}
	binary.LittleEndian.PutUint16(b[28:30], n)
	copy(b[30:286], r.filename)
	for i, a := range r.argv {
		if i >= MaxArgs {
			break
		}
		start := 286 + i*MaxArgLen
		copy(b[start:start+MaxArgLen], a)
	}
	return b
}

func args(ss ...string) [][]byte {
	out := make([][]byte, 0, len(ss))
	for _, s := range ss {
		out = append(out, []byte(s))
	}
	return out
}

func TestDecodeExecEvent(t *testing.T) {
	// Eight slots of exactly MaxArgLen bytes with no NUL: the widest argv the
	// kernel can produce, every argument truncated by the helper.
	maxArgv := make([][]byte, MaxArgs)
	wantMaxArgv := make([]string, MaxArgs)
	for i := range maxArgv {
		s := strings.Repeat(string(rune('a'+i)), MaxArgLen)
		maxArgv[i] = []byte(s)
		wantMaxArgv[i] = s
	}

	tests := []struct {
		name string
		rec  execRecord
		want runtimeevent.Event
	}{
		{
			name: "stdio mcp server via npx",
			rec: execRecord{
				cgroupID: 0x0807060504030201,
				pid:      2001,
				comm:     []byte("npx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
				filename: []byte("/usr/local/bin/npx\x00"),
				argv:     args("npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 0x0807060504030201,
				PID:      2001,
				Comm:     "npx",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/usr/local/bin/npx",
					Argv:     []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"},
				},
			},
		},
		{
			name: "no argv reported",
			rec: execRecord{
				cgroupID: 11,
				pid:      3,
				comm:     []byte("sh"),
				filename: []byte("/bin/sh"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 11,
				PID:      3,
				Comm:     "sh",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/bin/sh",
					Argv:     nil,
				},
			},
		},
		{
			name: "maximum argv: 8 slots, each unterminated at 128 bytes",
			rec: execRecord{
				cgroupID: 12,
				pid:      4,
				comm:     []byte("python3"),
				filename: []byte("/usr/bin/python3"),
				argv:     maxArgv,
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 12,
				PID:      4,
				Comm:     "python3",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/usr/bin/python3",
					Argv:     wantMaxArgv,
				},
			},
		},
		{
			name: "argv slots past the reported count are ignored",
			rec: execRecord{
				cgroupID: 13,
				comm:     []byte("uvx"),
				filename: []byte("/usr/bin/uvx"),
				argv:     args("uvx", "mcp-server-git", "LEFTOVER", "GARBAGE"),
				argvLen:  2,
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 13,
				Comm:     "uvx",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/usr/bin/uvx",
					Argv:     []string{"uvx", "mcp-server-git"},
				},
			},
		},
		{
			name: "empty argument is preserved, not dropped",
			rec: execRecord{
				cgroupID: 14,
				comm:     []byte("app"),
				filename: []byte("/app"),
				argv:     args("app", "", "--flag"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 14,
				Comm:     "app",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/app",
					Argv:     []string{"app", "", "--flag"},
				},
			},
		},
		{
			name: "comm without NUL terminator keeps all 16 bytes",
			rec: execRecord{
				cgroupID: 15,
				comm:     []byte("0123456789abcdef"),
				filename: []byte("/x"),
				argv:     args("x"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 15,
				Comm:     "0123456789abcdef",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/x",
					Argv:     []string{"x"},
				},
			},
		},
		{
			name: "filename without NUL terminator keeps all 256 bytes",
			rec: execRecord{
				cgroupID: 16,
				comm:     []byte("long"),
				filename: []byte(strings.Repeat("p", MaxFilename)),
				argv:     args("long"),
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 16,
				Comm:     "long",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: strings.Repeat("p", MaxFilename),
					Argv:     []string{"long"},
				},
			},
		},
		{
			name: "trailing struct padding is ignored",
			rec: execRecord{
				cgroupID: 17,
				comm:     []byte("docker"),
				filename: []byte("/usr/bin/docker"),
				argv:     args("docker", "run", "mcp/fetch"),
				pad:      2, // sizeof(struct exec_event) == 1312
			},
			want: runtimeevent.Event{
				Kind:     runtimeevent.KindExec,
				CgroupID: 17,
				Comm:     "docker",
				Count:    1,
				Exec: &runtimeevent.ExecFacts{
					Filename: "/usr/bin/docker",
					Argv:     []string{"docker", "run", "mcp/fetch"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeExecEvent(tc.rec.bytes())
			if err != nil {
				t.Fatalf("DecodeExecEvent() error = %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DecodeExecEvent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDecodeExecEvent_Errors(t *testing.T) {
	full := execRecord{comm: []byte("sh"), filename: []byte("/bin/sh"), argv: args("sh")}.bytes()

	tests := []struct {
		name    string
		in      []byte
		wantErr error
	}{
		{name: "nil buffer", in: nil, wantErr: ErrTruncated},
		{name: "empty buffer", in: []byte{}, wantErr: ErrTruncated},
		{name: "one byte short", in: full[:len(full)-1], wantErr: ErrTruncated},
		{name: "filename present but argv area cut off", in: full[:290], wantErr: ErrTruncated},
		{name: "seven of eight argv slots", in: full[:offArgv+7*MaxArgLen], wantErr: ErrTruncated},
		{
			name:    "argv count one past the maximum",
			in:      execRecord{argvLen: MaxArgs + 1, argv: args("a")}.bytes(),
			wantErr: ErrBadArgvLen,
		},
		{
			name:    "argv count absurd",
			in:      execRecord{argvLen: 0xffff, argv: args("a")}.bytes(),
			wantErr: ErrBadArgvLen,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeExecEvent(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeExecEvent() error = %v, want %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(runtimeevent.Event{}, got); diff != "" {
				t.Errorf("DecodeExecEvent() returned a partial event on error (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDecodeExecEvent_LittleEndian pins the byte order of every scalar field.
func TestDecodeExecEvent_LittleEndian(t *testing.T) {
	b := make([]byte, EventSize)
	copy(b[0:8], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	copy(b[8:12], []byte{0xd2, 0x04, 0x00, 0x00}) // 1234
	copy(b[12:28], []byte("go"))
	copy(b[28:30], []byte{0x01, 0x00}) // argv_len 1
	copy(b[30:286], []byte("/bin/true"))
	copy(b[286:286+MaxArgLen], []byte("true"))

	got, err := DecodeExecEvent(b)
	if err != nil {
		t.Fatalf("DecodeExecEvent() error = %v", err)
	}
	want := runtimeevent.Event{
		Kind:     runtimeevent.KindExec,
		CgroupID: 0x8877665544332211,
		PID:      1234,
		Comm:     "go",
		Count:    1,
		Exec: &runtimeevent.ExecFacts{
			Filename: "/bin/true",
			Argv:     []string{"true"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("DecodeExecEvent() mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeExecEvent_NeverPanics walks every truncation of a valid record and
// every argv_len value. Kernel bytes are untrusted: error, never panic.
func TestDecodeExecEvent_NeverPanics(t *testing.T) {
	full := execRecord{
		cgroupID: 1, pid: 2,
		comm:     []byte("fuzz"),
		filename: []byte("/bin/fuzz"),
		argv:     args("fuzz", "-x"),
	}.bytes()

	for i := 0; i <= len(full); i++ {
		_, err := DecodeExecEvent(full[:i])
		if i < EventSize && err == nil {
			t.Fatalf("DecodeExecEvent(prefix of %d bytes) unexpectedly succeeded", i)
		}
	}

	counts := []int{}
	for n := 0; n <= 300; n++ {
		counts = append(counts, n)
	}
	counts = append(counts, 1024, 0xffff)
	base := execRecord{argv: args("a", "b")}.bytes()
	for _, n := range counts {
		b := append([]byte(nil), base...)
		binary.LittleEndian.PutUint16(b[offArgvLen:offArgvLen+2], uint16(n))
		got, err := DecodeExecEvent(b)
		switch {
		case n <= MaxArgs:
			if err != nil {
				t.Fatalf("argv_len %d: unexpected error %v", n, err)
			}
			if len(got.Exec.Argv) != n {
				t.Fatalf("argv_len %d: decoded %d args", n, len(got.Exec.Argv))
			}
		default:
			if !errors.Is(err, ErrBadArgvLen) {
				t.Fatalf("argv_len %d: error = %v, want ErrBadArgvLen", n, err)
			}
		}
	}
}
