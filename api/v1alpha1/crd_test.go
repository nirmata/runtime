package v1alpha1

import (
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// crdDir is where `make generate-crds` writes controller-gen's output.
const crdDir = "../../charts/kyverno-runtime/crds"

// crd is the slice of a CustomResourceDefinition these tests assert on. The
// schema itself stays an untyped map so navigation failures point at the exact
// missing key instead of silently unmarshalling into a zero value.
type crd struct {
	Spec struct {
		Group string `json:"group"`
		Scope string `json:"scope"`
		Names struct {
			Kind       string   `json:"kind"`
			ListKind   string   `json:"listKind"`
			Plural     string   `json:"plural"`
			Singular   string   `json:"singular"`
			ShortNames []string `json:"shortNames"`
		} `json:"names"`
		Versions []struct {
			Name   string `json:"name"`
			Served bool   `json:"served"`
			Schema struct {
				OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
			} `json:"schema"`
			Subresources map[string]any `json:"subresources"`
		} `json:"versions"`
	} `json:"spec"`
}

// loadCRDRaw reads a generated CRD from the chart. A missing file means
// `make generate-crds` was not run after a types change.
func loadCRDRaw(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(crdDir, file))
	if err != nil {
		t.Fatalf("reading generated CRD (run `make generate-crds`): %v", err)
	}
	return data
}

func unmarshalCRD(t *testing.T, data []byte, into any) {
	t.Helper()
	if err := yaml.Unmarshal(data, into); err != nil {
		t.Fatalf("unmarshalling generated CRD: %v", err)
	}
}

// loadCRD reads and parses a generated CRD from the chart.
func loadCRD(t *testing.T, file string) crd {
	t.Helper()
	var out crd
	unmarshalCRD(t, loadCRDRaw(t, file), &out)
	if len(out.Spec.Versions) != 1 {
		t.Fatalf("%s: got %d versions, want exactly 1", file, len(out.Spec.Versions))
	}
	return out
}

// schema returns the v1alpha1 openAPIV3Schema of the CRD.
func (c crd) schema() map[string]any { return c.Spec.Versions[0].Schema.OpenAPIV3Schema }

// dig walks nested maps/arrays. Path elements are either string map keys or int
// array indices.
func dig(t *testing.T, root any, path ...any) any {
	t.Helper()
	cur := root
	for i, p := range path {
		switch key := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("dig %v: element %d (%q): parent is %T, not a map", path, i, key, cur)
			}
			cur, ok = m[key]
			if !ok {
				t.Fatalf("dig %v: element %d (%q) missing", path, i, key)
			}
		case int:
			a, ok := cur.([]any)
			if !ok {
				t.Fatalf("dig %v: element %d (%d): parent is %T, not an array", path, i, key, cur)
			}
			if key >= len(a) {
				t.Fatalf("dig %v: element %d: index %d out of range (len %d)", path, i, key, len(a))
			}
			cur = a[key]
		default:
			t.Fatalf("dig %v: element %d: unsupported path type %T", path, i, p)
		}
	}
	return cur
}

func digString(t *testing.T, root any, path ...any) string {
	t.Helper()
	v := dig(t, root, path...)
	s, ok := v.(string)
	if !ok {
		t.Fatalf("dig %v: got %T, want string", path, v)
	}
	return s
}

// digStrings reads a YAML string array (enums, listMapKeys, ...).
func digStrings(t *testing.T, root any, path ...any) []string {
	t.Helper()
	v := dig(t, root, path...)
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("dig %v: got %T, want array", path, v)
	}
	out := make([]string, 0, len(a))
	for i, e := range a {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("dig %v[%d]: got %T, want string", path, i, e)
		}
		out = append(out, s)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// specProp returns spec.<name> from a CRD schema.
func specProp(t *testing.T, c crd, name string) any {
	t.Helper()
	return dig(t, c.schema(), "properties", "spec", "properties", name)
}

// behaviorItems returns the schema of one entry of spec.behaviors.
func behaviorItems(t *testing.T, c crd) any {
	t.Helper()
	return dig(t, specProp(t, c, "behaviors"), "items")
}
