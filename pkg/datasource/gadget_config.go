package datasource

import (
	"fmt"
	"strings"
)

// gadgetRunConfig maps a GadgetCollectRequest into the gadget image name
// and parameter values needed by the Inspektor Gadget runtime.
func gadgetRunConfig(request GadgetCollectRequest) (string, map[string]string, error) {
	params := map[string]string{}
	for key, value := range request.Parameters {
		trimmedKey := strings.TrimSpace(strings.TrimPrefix(key, "--"))
		trimmedValue := strings.TrimSpace(value)
		if trimmedKey == "" || trimmedValue == "" || trimmedKey == "timeout" {
			continue
		}
		params[trimmedKey] = trimmedValue
	}

	switch strings.ToLower(strings.TrimSpace(request.EventType)) {
	case "open":
		return "trace_open", params, nil
	case "exec":
		return "trace_exec", params, nil
	case "connect", "tcpconnect":
		params["connect-only"] = "true"
		return "trace_tcp", params, nil
	default:
		return "", nil, fmt.Errorf("unsupported runtime event type %q", request.EventType)
	}
}

// matchesPod returns true if the event fields are compatible with the given
// namespace and pod name. Events without k8s metadata always match (they come
// from the node-wide eBPF capture and cannot be filtered by pod).
func matchesPod(fields map[string]string, namespace, pod string) bool {
	if namespace != "" {
		fieldNamespace := coalesceField(fields, "", "k8s.namespace", "namespace")
		if fieldNamespace != "" && fieldNamespace != namespace {
			return false
		}
	}
	if pod != "" {
		fieldPod := coalesceField(fields, "", "k8s.podName", "k8s.podname", "pod", "podName")
		if fieldPod != "" && fieldPod != pod {
			return false
		}
	}
	return true
}

// coalesceField returns the first non-empty value from the given keys in
// fields, or the fallback if none are found.
func coalesceField(fields map[string]string, fallback string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[key]); value != "" {
			return value
		}
	}
	return fallback
}

// normalizePacketEventType determines the canonical event type for an event.
// For non-network events, the requested type is preserved.
func normalizePacketEventType(fallback string, fields map[string]string) string {
	normalizedFallback := strings.ToLower(strings.TrimSpace(fallback))
	if strings.EqualFold(normalizedFallback, "connect") || strings.EqualFold(normalizedFallback, "tcpconnect") {
		if value := strings.TrimSpace(fields["l4proto"]); strings.EqualFold(value, "TCP") {
			return "tcpconnect"
		}
		return "connect"
	}

	// For non-network events, keep the requested type as the canonical type.
	// Some gadgets expose packet-level "event"/"type" values such as "normal"
	// that are not policy event names and would break validation matching.
	if normalizedFallback != "" {
		return normalizedFallback
	}

	if value := strings.TrimSpace(fields["event"]); value != "" {
		return strings.ToLower(value)
	}
	if value := strings.TrimSpace(fields["type"]); value != "" {
		return strings.ToLower(value)
	}

	return normalizedFallback
}
