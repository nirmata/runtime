package v1alpha1

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const aiInventoriesCRD = "runtime.kyverno.io_aiinventories.yaml"

// metav1.Time marshals at second precision, so fixtures must be second-aligned
// UTC for a JSON-based DeepCopy to round-trip exactly.
func fixedTime(offsetSeconds int) metav1.Time {
	return metav1.NewTime(time.Date(2026, 7, 27, 10, 0, offsetSeconds, 0, time.UTC))
}

func fullAIInventory() *AIInventory {
	return &AIInventory{
		TypeMeta: metav1.TypeMeta{
			APIVersion: GroupVersion.String(),
			Kind:       "AIInventory",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "cluster",
			Generation:  7,
			Labels:      map[string]string{"app.kubernetes.io/name": "kyverno-runtime"},
			Annotations: map[string]string{"runtime.kyverno.io/shards": "2"},
		},
		Status: AIInventoryStatus{
			Summary: AIInventorySummary{
				Workloads: 3,
				Providers: "anthropic,ollama,openai",
			},
			Nodes: []AINodeInventory{
				{
					NodeName:      "node-a",
					UpdatedAt:     fixedTime(0),
					DroppedEvents: 12,
					Workloads: []AIWorkloadInventory{
						{
							Namespace:       "team-a",
							Kind:            "Deployment",
							Name:            "agent",
							Classes:         []string{"llm", "mcp"},
							Providers:       []string{"anthropic", "openai"},
							EndpointKinds:   []string{"messages", "mcp.streamable-http"},
							Models:          []string{"claude-sonnet-4-5"},
							Transports:      []string{"https", "stdio"},
							EventCount:      41,
							UngovernedCount: 5,
							FirstSeen:       fixedTime(1),
							LastSeen:        fixedTime(2),
						},
						{
							Namespace: "team-b",
							Kind:      "Pod",
							Name:      "bare-pod",
							Classes:   []string{"a2a"},
						},
					},
				},
				{
					NodeName:  "node-b",
					UpdatedAt: fixedTime(3),
				},
			},
		},
	}
}

func TestAIInventoryDeepCopyObjectRoundTrip(t *testing.T) {
	in := fullAIInventory()

	obj := in.DeepCopyObject()
	out, ok := obj.(*AIInventory)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, want *AIInventory", obj)
	}
	if diff := cmp.Diff(in, out); diff != "" {
		t.Errorf("AIInventory did not survive DeepCopyObject (-want +got):\n%s", diff)
	}

	// Independence: mutating every nested reference type in the copy must not
	// reach the original.
	out.Labels["mutated"] = "yes"
	out.Status.Nodes[0].NodeName = "hijacked"
	out.Status.Nodes[0].Workloads[0].Classes[0] = "hijacked"
	out.Status.Nodes[0].Workloads = out.Status.Nodes[0].Workloads[:1]
	out.Status.Summary.Providers = "hijacked"

	if diff := cmp.Diff(fullAIInventory(), in); diff != "" {
		t.Errorf("mutating the copy changed the original (-want +got):\n%s", diff)
	}
}

func TestAIInventoryDeepCopyObjectNilReceiver(t *testing.T) {
	var in *AIInventory
	if got := in.DeepCopyObject(); got != nil {
		t.Errorf("(*AIInventory)(nil).DeepCopyObject() = %v, want nil", got)
	}
	var list *AIInventoryList
	if got := list.DeepCopyObject(); got != nil {
		t.Errorf("(*AIInventoryList)(nil).DeepCopyObject() = %v, want nil", got)
	}
}

func TestAIInventoryListDeepCopyObjectRoundTrip(t *testing.T) {
	in := &AIInventoryList{
		TypeMeta: metav1.TypeMeta{APIVersion: GroupVersion.String(), Kind: "AIInventoryList"},
		ListMeta: metav1.ListMeta{ResourceVersion: "1234"},
		Items:    []AIInventory{*fullAIInventory()},
	}
	obj := in.DeepCopyObject()
	out, ok := obj.(*AIInventoryList)
	if !ok {
		t.Fatalf("DeepCopyObject returned %T, want *AIInventoryList", obj)
	}
	if diff := cmp.Diff(in, out); diff != "" {
		t.Errorf("AIInventoryList did not survive DeepCopyObject (-want +got):\n%s", diff)
	}
}

func TestAIInventoryIsRegisteredInScheme(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	for _, kind := range []string{"AIInventory", "AIInventoryList"} {
		if _, err := s.New(GroupVersion.WithKind(kind)); err != nil {
			t.Errorf("scheme does not know %s: %v", kind, err)
		}
	}
}

func TestAIInventoryCRD_ClusterScopedSingletonWithNodeShards(t *testing.T) {
	c := loadCRD(t, aiInventoriesCRD)

	if c.Spec.Scope != "Cluster" {
		t.Errorf("scope = %q, want Cluster", c.Spec.Scope)
	}
	if c.Spec.Names.Plural != "aiinventories" {
		t.Errorf("plural = %q, want aiinventories", c.Spec.Names.Plural)
	}
	if !equalStrings(c.Spec.Names.ShortNames, []string{"aiinv"}) {
		t.Errorf("shortNames = %v, want [aiinv]", c.Spec.Names.ShortNames)
	}
	if _, ok := c.Spec.Versions[0].Subresources["status"]; !ok {
		t.Errorf("status subresource missing; the syncer writes status only")
	}

	nodes := dig(t, c.schema(), "properties", "status", "properties", "nodes")
	if got := digString(t, nodes, "x-kubernetes-list-type"); got != "map" {
		t.Errorf("status.nodes list type = %q, want map (per-node shards must merge, not clobber)", got)
	}
	if got := digStrings(t, nodes, "x-kubernetes-list-map-keys"); !equalStrings(got, []string{"nodeName"}) {
		t.Errorf("status.nodes list map keys = %v, want [nodeName]", got)
	}
	if got := digStrings(t, nodes, "items", "required"); !equalStrings(got, []string{"nodeName"}) {
		t.Errorf("status.nodes item required = %v, want [nodeName]", got)
	}

	// DroppedEvents must be surfaced: silence must never read as safety.
	if got := digString(t, nodes, "items", "properties", "droppedEvents", "format"); got != "int64" {
		t.Errorf("status.nodes[].droppedEvents format = %q, want int64", got)
	}

	wl := dig(t, nodes, "items", "properties", "workloads", "items")
	if got := digStrings(t, wl, "required"); !equalStrings(got, []string{"kind", "name", "namespace"}) {
		t.Errorf("workload required = %v, want [kind name namespace]", got)
	}
	for _, f := range []string{"classes", "providers", "endpointKinds", "models", "transports"} {
		if got := digString(t, wl, "properties", f, "items", "type"); got != "string" {
			t.Errorf("workload.%s item type = %q, want string", f, got)
		}
	}
	for _, f := range []string{"eventCount", "ungovernedCount"} {
		if got := digString(t, wl, "properties", f, "format"); got != "int64" {
			t.Errorf("workload.%s format = %q, want int64", f, got)
		}
	}

	summary := dig(t, c.schema(), "properties", "status", "properties", "summary")
	if got := digString(t, summary, "properties", "workloads", "format"); got != "int32" {
		t.Errorf("status.summary.workloads format = %q, want int32", got)
	}
	if got := digString(t, summary, "properties", "providers", "type"); got != "string" {
		t.Errorf("status.summary.providers type = %q, want string", got)
	}
}

func TestAIInventoryCRD_PrintColumns(t *testing.T) {
	data := loadCRDRaw(t, aiInventoriesCRD)
	var doc struct {
		Spec struct {
			Versions []struct {
				AdditionalPrinterColumns []struct {
					Name     string `json:"name"`
					Type     string `json:"type"`
					JSONPath string `json:"jsonPath"`
				} `json:"additionalPrinterColumns"`
			} `json:"versions"`
		} `json:"spec"`
	}
	unmarshalCRD(t, data, &doc)

	want := map[string]string{
		"Workloads": ".status.summary.workloads",
		"Providers": ".status.summary.providers",
		"Age":       ".metadata.creationTimestamp",
	}
	got := map[string]string{}
	for _, col := range doc.Spec.Versions[0].AdditionalPrinterColumns {
		got[col.Name] = col.JSONPath
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("printer columns (-want +got):\n%s", diff)
	}
}
