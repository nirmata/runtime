package examples_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const (
	policyAPIVersion = "runtime.nirmata.io/v1alpha1"
	policyKind       = "RuntimePolicy"
)

// Placeholders in *.tmpl.yaml examples, substituted before decoding. A token
// missing from this table survives into the manifest and fails validation,
// which is deliberate: a new placeholder must be registered here rather than
// silently skipped.
var templatePlaceholders = map[string]string{
	"ALLOWED_IP": "10.0.0.1",
	"DENIED_IP":  "10.0.0.2",
}

var skipDirs = map[string]bool{
	".git":         true,
	".claude":      true,
	"bin":          true,
	"vendor":       true,
	"node_modules": true,
}

type manifest struct {
	// repo-relative path, suffixed with a fence index for markdown and a
	// document index within a multi-document stream
	name string
	body []byte
}

// These manifests are compiled, never evaluated, so no Service value is ever
// looked up.
type resolveNothing struct{}

func (resolveNothing) ResolveService(namespace, name string) ([]string, bool) {
	return nil, false
}

func TestExampleAndDocumentedPoliciesAreValid(t *testing.T) {
	root := repoRoot(t)

	fromExamples := collectFromExamples(t, root)
	fromMarkdown := collectFromMarkdown(t, root)

	if len(fromExamples) == 0 {
		t.Errorf("no RuntimePolicy manifests found under %s: either the directory is missing or the walk matched nothing", filepath.Join(root, "examples"))
	}
	if len(fromMarkdown) == 0 {
		t.Errorf("no RuntimePolicy manifests found in fenced yaml blocks of any markdown file under %s", root)
	}
	t.Logf("validating %d RuntimePolicy manifests: %d from examples/, %d from markdown fences",
		len(fromExamples)+len(fromMarkdown), len(fromExamples), len(fromMarkdown))

	c, err := compiler.NewCompiler(nil, resolveNothing{})
	if err != nil {
		t.Fatalf("compiler.NewCompiler: %v", err)
	}

	for _, m := range append(fromExamples, fromMarkdown...) {
		t.Run(m.name, func(t *testing.T) {
			rp, err := decodeStrict(m.body)
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			for i, b := range rp.Spec.Behaviors {
				n := 0
				var kinds []string
				if b.Network != nil {
					n, kinds = n+1, append(kinds, "network")
				}
				if b.Exec != nil {
					n, kinds = n+1, append(kinds, "exec")
				}
				if b.Open != nil {
					n, kinds = n+1, append(kinds, "open")
				}
				if n != 1 {
					t.Errorf("spec.behaviors[%d]: got %d of network/exec/open (%v), want exactly one; the CRD rejects anything else", i, n, kinds)
				}
			}
			if rp.Spec.Mode == nil {
				t.Errorf("spec.mode is unset: a policy with no mode neither enforces nor reports")
			}
			if _, err := c.Compile(*rp); err != nil {
				t.Errorf("compile: %v", err)
			}
		})
	}
}

func decodeStrict(doc []byte) (*v1alpha1.RuntimePolicy, error) {
	asJSON, err := utilyaml.ToJSON(doc)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(asJSON))
	dec.DisallowUnknownFields()
	var rp v1alpha1.RuntimePolicy
	if err := dec.Decode(&rp); err != nil {
		return nil, err
	}
	return &rp, nil
}

func collectFromExamples(t *testing.T, root string) []manifest {
	t.Helper()
	var out []manifest
	dir := filepath.Join(root, "examples")
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel := relPath(root, path)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".tmpl.yaml") || strings.HasSuffix(path, ".tmpl.yml") {
			var applied []string
			for token, value := range templatePlaceholders {
				if bytes.Contains(body, []byte(token)) {
					body = bytes.ReplaceAll(body, []byte(token), []byte(value))
					applied = append(applied, token)
				}
			}
			if len(applied) == 0 {
				t.Errorf("%s: template file substituted no placeholder; add its token to templatePlaceholders", rel)
			}
		}
		out = append(out, policyDocs(t, rel, body)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk examples: %v", err)
	}
	return out
}

func collectFromMarkdown(t *testing.T, root string) []manifest {
	t.Helper()
	var out []manifest
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel := relPath(root, path)
		for i, fence := range yamlFences(body) {
			if !strings.Contains(fence, policyAPIVersion) {
				continue
			}
			out = append(out, policyDocs(t, fmt.Sprintf("%s#yaml-fence-%d", rel, i+1), []byte(fence))...)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk markdown: %v", err)
	}
	return out
}

// policyDocs splits a possibly multi-document YAML stream and keeps only the
// documents that declare the RuntimePolicy group/version/kind.
func policyDocs(t *testing.T, name string, body []byte) []manifest {
	t.Helper()
	var out []manifest
	r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(body)))
	for i := 0; ; i++ {
		doc, err := r.Read()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Errorf("%s: split documents: %v", name, err)
			return out
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var id struct {
			APIVersion string `json:"apiVersion"`
			Kind       string `json:"kind"`
		}
		asJSON, err := utilyaml.ToJSON(doc)
		if err != nil {
			t.Errorf("%s (document %d): not valid yaml: %v", name, i, err)
			continue
		}
		if err := json.Unmarshal(asJSON, &id); err != nil {
			continue
		}
		if id.APIVersion != policyAPIVersion || id.Kind != policyKind {
			continue
		}
		label := name
		if i > 0 {
			label = fmt.Sprintf("%s#doc-%d", name, i)
		}
		out = append(out, manifest{name: label, body: doc})
	}
}

// yamlFences returns the body of every fenced block whose info string is yaml,
// dedented by the indentation of its opening fence.
func yamlFences(src []byte) []string {
	var out []string
	lines := strings.Split(string(src), "\n")
	for i := 0; i < len(lines); i++ {
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " \t"))
		open := lines[i][indent:]
		if !strings.HasPrefix(open, "```") {
			continue
		}
		ticks := len(open) - len(strings.TrimLeft(open, "`"))
		marker := open[:ticks]
		info := strings.TrimSpace(open[ticks:])
		var body []string
		i++
		for ; i < len(lines); i++ {
			trimmed := strings.TrimLeft(lines[i], " \t")
			if strings.HasPrefix(trimmed, marker) && strings.TrimLeft(trimmed, "`") == "" {
				break
			}
			body = append(body, dedent(lines[i], indent))
		}
		if info == "yaml" || info == "yml" {
			out = append(out, strings.Join(body, "\n"))
		}
	}
	return out
}

func dedent(line string, n int) string {
	for i := 0; i < n && len(line) > 0 && (line[0] == ' ' || line[0] == '\t'); i++ {
		line = line[1:]
	}
	return line
}

func relPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}
