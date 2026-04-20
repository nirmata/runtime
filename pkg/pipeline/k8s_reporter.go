package pipeline

import (
	"context"
	"crypto/sha1"
	"fmt"
	"strings"
	"time"

	policyreportv1alpha2 "github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

const maxPolicyReportResults = 20

// K8sReporter writes PolicyReport resources to Kubernetes.
type K8sReporter struct {
	client client.Client
}

// NewK8sReporter creates a new K8sReporter.
func NewK8sReporter(c client.Client) *K8sReporter {
	return &K8sReporter{client: c}
}

// Report writes or updates a PolicyReport for the given findings.
func (r *K8sReporter) Report(ctx context.Context, req ReportRequest) error {
	if len(req.Findings) == 0 {
		return nil
	}

	reportName := reportName(req.Pod.Name, req.Policy.Name)
	existing := &policyreportv1alpha2.PolicyReport{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Pod.Namespace, Name: reportName}, existing)

	results := buildPolicyReportResults(req.Pod, req.Policy, req.Findings)

	if apierrors.IsNotFound(err) {
		bounded := truncatePolicyReportResults(results)
		obj := &policyreportv1alpha2.PolicyReport{
			TypeMeta: metav1.TypeMeta{APIVersion: policyreportv1alpha2.SchemeGroupVersion.String(), Kind: "PolicyReport"},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: req.Pod.Namespace,
				Name:      reportName,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "kyverno-runtime",
					"runtime.kyverno.io/policy":    req.Policy.Name,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       req.Pod.Name,
					UID:        req.Pod.UID,
				}},
			},
			Scope:   podReference(req.Pod),
			Results: bounded,
			Summary: summarizePolicyReportResults(bounded),
		}
		return r.client.Create(ctx, obj)
	}
	if err != nil {
		return err
	}

	existing.Results = truncatePolicyReportResults(append(existing.Results, results...))
	existing.Summary = summarizePolicyReportResults(existing.Results)
	return r.client.Update(ctx, existing)
}

func reportName(podName, policyName string) string {
	hash := sha1.Sum([]byte(fmt.Sprintf("%s-%s", podName, policyName)))
	return fmt.Sprintf("%s-%x", podName, hash[:5])
}

func podReference(pod *corev1.Pod) *corev1.ObjectReference {
	return &corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "Pod",
		Namespace:  pod.Namespace,
		Name:       pod.Name,
		UID:        pod.UID,
	}
}

func buildPolicyReportResults(pod *corev1.Pod, policy *v1alpha1.RuntimePolicy, findings []v1alpha1.RuleFinding) []policyreportv1alpha2.PolicyReportResult {
	results := make([]policyreportv1alpha2.PolicyReportResult, 0, len(findings))
	for _, finding := range findings {
		properties := make(map[string]string, len(finding.Fields)+1)
		for key, value := range finding.Fields {
			properties[key] = value
		}
		if finding.EventType != "" {
			properties["eventType"] = finding.EventType
		}

		result := policyreportv1alpha2.PolicyReportResult{
			Source:     "kyverno-runtime",
			Policy:     policy.Name,
			Rule:       finding.RuleName,
			Resources:  []corev1.ObjectReference{*podReference(pod)},
			Message:    finding.Message,
			Result:     reportResultForSeverity(finding.Severity),
			Scored:     true,
			Severity:   policyreportv1alpha2.PolicySeverity(strings.ToLower(strings.TrimSpace(finding.Severity))),
			Category:   "Runtime Security",
			Timestamp:  metav1.Timestamp{Seconds: time.Now().Unix()},
			Properties: properties,
		}
		results = append(results, result)
	}
	return results
}

func reportResultForSeverity(severity string) policyreportv1alpha2.PolicyResult {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info", "low":
		return policyreportv1alpha2.StatusWarn
	default:
		return policyreportv1alpha2.StatusFail
	}
}

func summarizePolicyReportResults(results []policyreportv1alpha2.PolicyReportResult) policyreportv1alpha2.PolicyReportSummary {
	summary := policyreportv1alpha2.PolicyReportSummary{}
	for _, result := range results {
		switch result.Result {
		case policyreportv1alpha2.StatusPass:
			summary.Pass++
		case policyreportv1alpha2.StatusWarn:
			summary.Warn++
		case policyreportv1alpha2.StatusSkip:
			summary.Skip++
		case policyreportv1alpha2.StatusError:
			summary.Error++
		default:
			summary.Fail++
		}
	}
	return summary
}

func truncatePolicyReportResults(results []policyreportv1alpha2.PolicyReportResult) []policyreportv1alpha2.PolicyReportResult {
	if len(results) > maxPolicyReportResults {
		return results[:maxPolicyReportResults]
	}
	return results
}
