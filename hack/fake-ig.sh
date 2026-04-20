#!/usr/bin/env sh
# Minimal fake inspektor gadget binary for local e2e wiring validation.
echo '{"event":"connect","destination":{"ip":"8.8.8.8","port":5432},"anomaly":{"baseline_deviation":4.2},"pod":{"labels":{"audit-enabled":"true"}},"syscall":{"latency_us":25000},"container":{"privileged":true},"process":{"name":"/bin/sh"},"file":{"path":"/etc/kubernetes/pki/apiserver.key"}}'
