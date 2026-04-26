package observability

import "testing"

func TestIncEvaluatorCompileError(t *testing.T) {
	IncEvaluatorCompileError("test-policy")
}

func TestNormalizeLabel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{name: "empty", in: "", out: "unknown"},
		{name: "trim and lower", in: "  ExEc  ", out: "exec"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeLabel(tt.in); got != tt.out {
				t.Fatalf("normalizeLabel(%q) = %q, want %q", tt.in, got, tt.out)
			}
		})
	}
}
