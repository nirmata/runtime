# WorkloadProfile (learning mode)

> **Status: experimental.** A `WorkloadProfile` has no effect unless the workload-profile controller (`kyverno-runtime ctrl`, Helm: `ctrl.enabled=true`) is running.

`WorkloadProfile` is a cluster-scoped CRD. It specifies `behaviorsToLearn` and a
`duration`. Currently, `behaviorsToLearn` is not yet plumbed through to the daemons,
and learning mode records observed behavior while enforcement still applies.

`kyverno-runtime ctrl` watches `WorkloadProfile` objects and calls each daemon's
gRPC API to start/stop learning windows.

## Example: WorkloadProfile

```yaml
apiVersion: runtime.kyverno.io/v1alpha1
kind: WorkloadProfile
metadata:
  name: nginx-learn
spec:
  behaviorsToLearn:
  - network
  - open
  duration: 10m
```

```bash
kubectl apply -f nginx-learn.yaml
kubectl get workloadprofile nginx-learn
```
