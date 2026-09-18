package compiler

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParsePathValue(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantStar   bool
		wantPath   string
		wantPrefix string
		wantErr    error
	}{
		{name: "absolute path", in: "/usr/bin/curl", wantPath: "/usr/bin/curl"},
		{name: "bare program name rejected", in: "kubectl", wantErr: ErrRelativePathValue},
		{name: "path with spaces inside", in: "/opt/my app/run", wantPath: "/opt/my app/run"},
		{name: "path with brackets", in: "/tmp/[cache]/bin", wantPath: "/tmp/[cache]/bin"},
		{name: "path with quotes", in: `/tmp/"odd"/bin`, wantPath: `/tmp/"odd"/bin`},
		{name: "directory prefix", in: "/usr/lib/*", wantPrefix: "/usr/lib/"},
		{name: "root prefix", in: "/*", wantPrefix: "/"},
		{name: "prefix with surrounding whitespace trimmed", in: " /usr/lib/*\n", wantPrefix: "/usr/lib/"},
		{name: "interior star rejected", in: "/usr/*/bin", wantErr: ErrStarInPathValue},
		{name: "double star rejected", in: "/usr/lib/**", wantErr: ErrStarInPathValue},
		{name: "star without a separator rejected", in: "/usr/lib*", wantErr: ErrStarInPathValue},
		{name: "star in the prefix body rejected", in: "/usr/*/lib/*", wantErr: ErrStarInPathValue},
		{name: "trailing separator rejected", in: "/usr/lib/", wantErr: ErrTrailingSlashPathValue},
		{name: "root alone rejected", in: "/", wantErr: ErrTrailingSlashPathValue},
		{name: "argv-looking value rejected, and would be one literal path anyway", in: "kubectl delete", wantErr: ErrRelativePathValue},
		{name: "dot-relative rejected", in: "./relative", wantErr: ErrRelativePathValue},
		{name: "parent-relative rejected", in: "../up", wantErr: ErrRelativePathValue},
		{name: "surrounding whitespace trimmed", in: "  /bin/sh\t", wantPath: "/bin/sh"},
		{name: "trailing newline from a YAML block scalar", in: "/bin/sh\n", wantPath: "/bin/sh"},
		{name: "carriage return and newline", in: "/bin/sh\r\n", wantPath: "/bin/sh"},
		{name: "default deny sentinel", in: StarTarget, wantStar: true},
		{name: "padded sentinel rejected", in: " * ", wantErr: ErrPaddedStarValue},
		{name: "sentinel with trailing newline rejected", in: "*\n", wantErr: ErrPaddedStarValue},
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
			if got.Prefix != tt.wantPrefix {
				t.Errorf("Prefix = %q, want %q", got.Prefix, tt.wantPrefix)
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

func TestParsePathList(t *testing.T) {
	values := []string{
		"/bin/sh",
		"/usr/lib/*",
		" /bin/sh ",
		"/usr/lib/*",
		StarTarget,
		"kubectl",
	}

	paths, prefixes, star, rejected := ParsePathList(values)

	if want := []string{"/bin/sh"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	if want := []string{"/usr/lib/"}; !slices.Equal(prefixes, want) {
		t.Errorf("prefixes = %q, want %q", prefixes, want)
	}
	if !star {
		t.Error("star = false, want true")
	}
	if len(rejected) != 1 || rejected[0].Value != "kubectl" {
		t.Errorf("rejected = %+v, want only kubectl", rejected)
	}
}

func TestAncestorDirs(t *testing.T) {
	deep := "/" + strings.Repeat("a/", MaxPrefixDepth+4) + "file"

	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "root", in: "/bin", want: []string{"/"}},
		{name: "nested", in: "/usr/lib/libc.so", want: []string{"/", "/usr/", "/usr/lib/"}},
		{name: "relative never yields the root", in: "bin/sh", want: []string{"bin/"}},
		{name: "empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AncestorDirs(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("AncestorDirs(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	got := AncestorDirs(deep)
	if len(got) != MaxPrefixDepth {
		t.Fatalf("AncestorDirs on a %d-component path returned %d dirs, want the %d-deep bound", MaxPrefixDepth+4, len(got), MaxPrefixDepth)
	}
	if last := got[len(got)-1]; strings.Count(last, "/") != MaxPrefixDepth {
		t.Errorf("deepest dir %q does not sit at the bound", last)
	}
}
