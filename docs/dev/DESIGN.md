# Kyverno Runtime Prototype Design

## Goal

`kyverno-runtime` runs as a single-process runtime policy controller packaged as a
DaemonSet. It evaluates Pods against runtime-oriented policies and writes findings
into namespaced `PolicyReport` resources, using the same reporting surface Kyverno
already exposes.

The current implementation is a collapsed model: controller, collection,
evaluation, and reporting are all in one binary/process (`cmd/kyverno-runtime`).

For runtime baseline data modeling in kyverno-runtime, the canonical CR name is
`RuntimeBehavior`.

## Architecture Overview

`kyverno-runtime` is a modular DaemonSet controller with clean separation between
policy matching, event collection, evaluation, and reporting, but these modules
run in one process:

### Controller (DaemonSet Pods, One Active Reconciler by Default)

- Watches Pod resources in the cluster
- Lists all `RuntimePolicy` resources
- **Matches** policies to pods using `matchConstraints` and selectors
- **Collects** runtime events using embedded Inspektor Gadget local runtime
- **Evaluates** policies against events using CEL expressions
- **Reports** findings in `PolicyReport` resources
- Runs as a DaemonSet in `kyverno-runtime` namespace

This model eliminates the previous controller/sensor network hop.

Important current behavior:

- The reconciler does not filter pods by node name.
- Deployment defaults to leader election enabled.
- In that default mode, a single active controller instance reconciles cluster
  pods and performs runtime collection from the node where that active instance
  is running.

## Component Responsibilities

### DaemonSet Controller

The controller is composed of four modular pipeline components that process each
reconciled pod through the same pipeline:

#### 1. Matcher

- Validates policy `matchConstraints` (resource/namespace/object rules)
- Checks `namespaceSelector` against pod's namespace labels
- Determines which policies apply to this pod

#### 2. Collector

- Uses `pkg/datasource/inspektor_gadget_source.go`
- Invokes Inspektor Gadget via embedded local runtime
- Uses execution timeout (default 8 seconds) and collection window (default 5 seconds)
- Captures runtime events matching the event types needed by applicable policies
- Returns events as structured data

#### 3. Evaluator

- For each policy, evaluates `matchConditions` (pre-conditions that must all pass)
- If matchConditions pass, evaluates policy `conditions` (CEL expressions over events)
- Generates findings for events that match conditions and severity levels

#### 4. Reporter

- Creates or updates `PolicyReport` resources in the pod's namespace
- Appends findings to report results array (max 20 recent results)
- Updates summary counts and severity tallies

#### Reconciliation Loop:

- Triggered by Pod watch events and explicitly requeued every 15 minutes
- Requeued every 15 minutes to catch new events
- Processes policies per pod through the pipeline manager

## Communication Protocol

### Pipeline Processing Model

Policies apply in a hierarchical filtering model on each pod:

``` text
1. Policy-level matching (matchConstraints — resource/namespace/object rules)
   ↓
   Does policy matchConstraints + selectors match this pod?
   (resourceRules + excludeResourceRules + namespaceSelector + objectSelector)
   ↓ YES
2. Event collection (local Inspektor Gadget)
   ↓
   Collect events for event types needed by this policy
   ↓
3. Validation-level filtering (CEL-based)
   ↓
   Do matchConditions apply to this event?
   (all conditions must pass)
   ↓ YES
4. Validation-level evaluation (CEL-based)
   ↓
   Do conditions match this event?
   (generate findings if all match)
   ↓
5. Report writing
   ↓
   Append findings to PolicyReport
```

#### Local Execution Model

- Event collection, evaluation, and reporting happen inside the same process
- No separate sensor service is required in the main runtime path
- Kubernetes API server is used for policy listing and PolicyReport writes

## Deployment Model

### Single DaemonSet Controller

``` text
DaemonSet Pod (Every Node)
    |
    +---> Inspektor Gadget (embedded local runtime)
    |       |
    |       +---> IG Collection (exec, open, connect)
    |
    +---> Matcher (policy selection)
    |
    +---> Evaluator (CEL expressions)
    |
    +---> Reporter (PolicyReport writer)
    |
    v
API Server
    |
    +---> PolicyReport resources
```

**Key design:**

- Single binary, DaemonSet deployment
- No sensor DaemonSet/service in the current runtime execution path
- Policies are listed from API server per reconciliation
- Reports are written directly to the API server
- Stateless pipeline: no long-lived per-pod event cache

### Current Deployment Semantics

- `cmd/kyverno-runtime/main.go` wires matcher, collector, evaluator, and reporter
  into one reconciler.
- Helm and raw manifests deploy this as a DaemonSet.
- Leader election is enabled by default in chart values and manager manifests.
- Because the reconciler has no nodeName filter, behavior is effectively
  single-active-controller unless leader election is disabled.

## Example Workflow

### Scenario: Detect shell execution in production pods

**Setup:**

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: RuntimePolicy
metadata:
  name: block-shell-escalation
spec:
  matchConstraints:
    namespaceSelector:
      matchLabels:
        env: production
    resourceRules:
    - apiGroups: [""]
      resources: ["pods"]
  validations:
  - name: detect-shell
    event: exec
    message: Shell execution detected
    severity: high
    matchConditions:
    - name: not-system-pod
      expression: pod.metadata.labels.system != "true"
    conditions:
    - expression: event["process.name"] == "/bin/sh"
    actions:
    - type: terminate
```

**Step-by-step execution (current behavior):**

1. **Active controller instance reconciles a pod**
   - Pod exists in `production` namespace (labeled `env=production`)
   - Reconciliation triggered on pod create/update

2. **Policy matching**
   - Matcher checks: does `matchConstraints` match this pod? ✓
   - Checks: namespace selector match? ✓ (env=production)
   - Checks: pod is a "pods" resource? ✓
   - Result: policy applies to this pod

3. **Event collection (embedded IG local runtime)**
   - Collector extracts event types: `["exec"]`
   - Invokes Inspektor Gadget embedded runtime in-process
   - Gadget collects for 5 seconds, capturing exec events from this pod
   - Events are filtered by pod namespace/name

4. **Policy evaluation**
   - Evaluator processes events
   - For each validation, evaluates matchConditions:
     - `not-system-pod`: checks if pod.metadata.labels.system != "true"
       → ✓ passes
   - Matchconditions passed, now evaluates main conditions:
     - For each event, evaluates CEL condition:
       `event["process.name"] == "/bin/sh"`
     - If match: create finding with severity=high

5. **Report generation**
   - Reporter creates/updates PolicyReport named
     `pod-name-<hash>-block-shell-escalation`
   - Appends finding to results array (max 20 recent findings)
   - Summary counts violations

6. **User inspection**

   ```bash
   kubectl get policyreport -n production
   kubectl get policyreport pod-name-xxxx -n production -o yaml
   ```

## Why This Design

### Separation of Concerns

The pipeline is modular, with each component as a replaceable interface:

- **Matcher**: Policy selection logic (can swap label selector implementations)
- **Collector**: Event collection (can swap Inspektor Gadget for eBPF, syscall hooks, etc.)
- **Evaluator**: CEL evaluation (can evolve without touching collection)
- **Reporter**: Report writing (can write to different storage backends)

Each component has unit tests and mocks for easy testing.

### Simplicity

- Single binary to build, test, and deploy
- No controller-to-sensor RPC path in the current runtime flow
- Straightforward pipeline wiring through interfaces (matcher/collector/evaluator/reporter)

### Scalability

- Collection cost is bounded by policy event types and gadget timeouts
- Stateless DaemonSet pods can be restarted freely
- With leader election enabled, only one active reconciler handles the queue

### Extensibility

- Each pipeline component is an interface; mock implementations exist for testing
- Policy-level control is already available (`matchConstraints`)
- CEL expressions allow fine-grained event filtering without code changes
- Validation-level `matchConditions` enable composable pre-filtering
- A standalone sensor package exists in the repo, but is not on the main
  runtime path used by `cmd/kyverno-runtime`

## Future Extensions

- **Real-time streaming**: Replace periodic reconciliation with event-driven
  streaming from Inspektor Gadget for sub-second detection
- **Action execution**: Implement the `actions` field to terminate pods or
  trigger webhooks on policy violations
- **Multi-event correlation**: Correlate events across time and pods for
  more sophisticated attack pattern detection
- **Report aggregation**: Optionally collect reports from all nodes to a
  central policyreport-aggregator for cluster-wide visibility
- **Collection plugins**: Add other collectors (syscall tracing, network
  monitoring, file access) beyond Inspektor Gadget as additional pipeline
  backends
