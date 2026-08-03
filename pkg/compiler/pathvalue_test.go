package compiler

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePathValue(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantStar bool
		wantPath string
		wantErr  error
	}{
		{name: "absolute path", in: "/usr/bin/curl", wantPath: "/usr/bin/curl"},
		{name: "bare program name rejected", in: "kubectl", wantErr: ErrRelativePathValue},
		{name: "path with spaces inside", in: "/opt/my app/run", wantPath: "/opt/my app/run"},
		{name: "path with brackets", in: "/tmp/[cache]/bin", wantPath: "/tmp/[cache]/bin"},
		{name: "path with quotes", in: `/tmp/"odd"/bin`, wantPath: `/tmp/"odd"/bin`},
		{name: "interior star is a literal, not a glob", in: "/usr/bin/*", wantPath: "/usr/bin/*"},
		{name: "argv-looking value rejected, and would be one literal path anyway", in: "kubectl delete", wantErr: ErrRelativePathValue},
		{name: "dot-relative rejected", in: "./relative", wantErr: ErrRelativePathValue},
		{name: "parent-relative rejected", in: "../up", wantErr: ErrRelativePathValue},
		{name: "surrounding whitespace trimmed", in: "  /bin/sh\t", wantPath: "/bin/sh"},
		{name: "trailing newline from a YAML block scalar", in: "/bin/sh\n", wantPath: "/bin/sh"},
		{name: "carriage return and newline", in: "/bin/sh\r\n", wantPath: "/bin/sh"},
		{name: "default deny sentinel", in: StarTarget, wantStar: true},
		{name: "padded sentinel", in: " * ", wantStar: true},
		{name: "longest accepted path", in: "/" + strings.Repeat("a", MaxPathValueLen-1), wantPath: "/" + strings.Repeat("a", MaxPathValueLen-1)},

		{name: "empty rejected", in: "", wantErr: ErrEmptyPathValue},
		{name: "whitespace only rejected", in: " \t\r\n", wantErr: ErrEmptyPathValue},
		{name: "embedded NUL rejected", in: "/bin/sh\x00/etc", wantErr: ErrNULInPathValue},
		{name: "trailing NUL rejected", in: "/bin/sh\x00", wantErr: ErrNULInPathValue},
		{name: "one byte over the limit rejected", in: "/" + strings.Repeat("a", MaxPathValueLen), wantErr: ErrPathValueTooLong},
		{name: "far over the limit rejected", in: strings.Repeat("/deep", 200), wantErr: ErrPathValueTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePathValue(tt.in)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParsePathValue(%q) error = %v, want %v", tt.in, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePathValue(%q) unexpected error = %v", tt.in, err)
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

// TestPathValuePreservesLiteralPaths pins the compatibility theorem: a value
// the kernel maps can hold comes back byte for byte, so the parser can never
// change which path a policy matches. Only surrounding whitespace is removed,
// and a path carrying it could never equal a kernel-resolved path anyway.
func TestPathValuePreservesLiteralPaths(t *testing.T) {
	paths := []string{
		"/bin/sh",
		"/usr/bin/curl",
		"/usr/local/bin/python3.12",
		"/opt/app/bin/my-binary",
		"/opt/my app/run",
		`/tmp/"odd"/[dir]/bin`,
		"/usr/bin/*",
		"/tmp/x'y",

		"/" + strings.Repeat("a", MaxPathValueLen-1),
		"/eé中/bin",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			got, err := ParsePathValue(p)
			if err != nil {
				t.Fatalf("ParsePathValue(%q) unexpected error = %v", p, err)
			}
			if got.Star {
				t.Fatalf("ParsePathValue(%q) reported the default-deny sentinel", p)
			}
			if got.Path != p {
				t.Errorf("ParsePathValue(%q).Path = %q, want the value unchanged", p, got.Path)
			}
		})
	}
}
