package compiler

import (
	"errors"
	"strings"
	"testing"
)

func TestParseExecValue(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantStar bool
		wantPath string
		wantErr  error
	}{
		{name: "absolute path", in: "/usr/bin/curl", wantPath: "/usr/bin/curl"},
		{name: "bare program name", in: "kubectl", wantPath: "kubectl"},
		{name: "path with spaces inside", in: "/opt/my app/run", wantPath: "/opt/my app/run"},
		{name: "path with brackets", in: "/tmp/[cache]/bin", wantPath: "/tmp/[cache]/bin"},
		{name: "path with quotes", in: `/tmp/"odd"/bin`, wantPath: `/tmp/"odd"/bin`},
		{name: "interior star is a literal, not a glob", in: "/usr/bin/*", wantPath: "/usr/bin/*"},
		{name: "argv-looking value is one literal path", in: "kubectl delete", wantPath: "kubectl delete"},
		{name: "surrounding whitespace trimmed", in: "  /bin/sh\t", wantPath: "/bin/sh"},
		{name: "trailing newline from a YAML block scalar", in: "/bin/sh\n", wantPath: "/bin/sh"},
		{name: "carriage return and newline", in: "/bin/sh\r\n", wantPath: "/bin/sh"},
		{name: "default deny sentinel", in: StarTarget, wantStar: true},
		{name: "padded sentinel", in: " * ", wantStar: true},
		{name: "longest accepted path", in: "/" + strings.Repeat("a", MaxExecPathLen-1), wantPath: "/" + strings.Repeat("a", MaxExecPathLen-1)},

		{name: "empty rejected", in: "", wantErr: ErrEmptyExecValue},
		{name: "whitespace only rejected", in: " \t\r\n", wantErr: ErrEmptyExecValue},
		{name: "embedded NUL rejected", in: "/bin/sh\x00/etc", wantErr: ErrNULInExecValue},
		{name: "trailing NUL rejected", in: "/bin/sh\x00", wantErr: ErrNULInExecValue},
		{name: "one byte over the limit rejected", in: "/" + strings.Repeat("a", MaxExecPathLen), wantErr: ErrExecValueTooLong},
		{name: "far over the limit rejected", in: strings.Repeat("/deep", 200), wantErr: ErrExecValueTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseExecValue(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseExecValue(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseExecValue(%q) unexpected error = %v", tt.in, err)
			}
			if got.Star != tt.wantStar {
				t.Errorf("Star = %v, want %v", got.Star, tt.wantStar)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
		})
	}
}

// TestExecValuePreservesLiteralPaths pins the compatibility theorem: a value
// the kernel maps can hold comes back byte for byte, so the parser can never
// change which path a policy matches. Only surrounding whitespace is removed,
// and a path carrying it could never equal a kernel-resolved path anyway.
func TestExecValuePreservesLiteralPaths(t *testing.T) {
	paths := []string{
		"/bin/sh",
		"/usr/bin/curl",
		"/usr/local/bin/python3.12",
		"/opt/app/bin/my-binary",
		"/opt/my app/run",
		`/tmp/"odd"/[dir]/bin`,
		"/usr/bin/*",
		"/tmp/x'y",
		"kubectl",
		"./relative",
		"../up",
		"/" + strings.Repeat("a", MaxExecPathLen-1),
		"/eé中/bin",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			got, err := ParseExecValue(p)
			if err != nil {
				t.Fatalf("ParseExecValue(%q) unexpected error = %v", p, err)
			}
			if got.Star {
				t.Fatalf("ParseExecValue(%q) reported the default-deny sentinel", p)
			}
			if got.Path != p {
				t.Errorf("ParseExecValue(%q).Path = %q, want the value unchanged", p, got.Path)
			}
		})
	}
}
