# WorkloadProfile (learning mode)

> **Status: not fully active.** Deploying a `WorkloadProfile` right now does
> nothing.

`WorkloadProfile` is a cluster-scoped CRD. It specifies `behaviorsToLearn` and a
`duration`, and triggers a bounded learning window during which matched behavior
is recorded instead of enforced, without needing an a-priori allow/deny list.

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
