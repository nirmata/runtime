package pipeline

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

// ReportRequest contains the data needed to write a PolicyReport.
type ReportRequest struct {
	Pod      *corev1.Pod
	Policy   *v1alpha1.RuntimePolicy
	Findings []v1alpha1.RuleFinding
}

// Reporter writes PolicyReport resources for policy findings.
type Reporter interface {
	// Report writes a PolicyReport for the given findings.
	// If findings are empty, may skip writing or update an existing report.
	Report(ctx context.Context, req ReportRequest) error
}
