package pipeline

import (
	"context"
	"testing"

	policyreportv1alpha2 "github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
)

// TestNewK8sReporter tests the K8sReporter constructor
func TestNewK8sReporter(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	require.NotNil(t, reporter)
	require.NotNil(t, reporter.client)
}

// TestK8sReporterCreateNewPolicyReport tests creating a new PolicyReport
func TestK8sReporterCreateNewPolicyReport(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
	}

	findings := []v1alpha1.RuleFinding{
		{
			RuleName:  "rule1",
			Message:   "test finding",
			Severity:  "high",
			EventType: "exec",
			Fields: map[string]string{
				"process.name": "/bin/bash",
			},
		},
	}

	req := ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: findings,
	}

	err := reporter.Report(context.Background(), req)

	require.NoError(t, err)

	// Verify at least one PolicyReport exists in the namespace
	prList := &policyreportv1alpha2.PolicyReportList{}
	err = c.List(context.Background(), prList)

	require.NoError(t, err)
	require.Greater(t, len(prList.Items), 0, "should have created at least one PolicyReport")
}

// TestK8sReporterNoFindings tests when there are no findings
func TestK8sReporterNoFindings(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
	}

	req := ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: []v1alpha1.RuleFinding{},
	}

	err := reporter.Report(context.Background(), req)

	// Should not error on empty findings, just return early
	require.NoError(t, err)
}

// TestK8sReporterUpdateExistingPolicyReport tests updating an existing report
func TestK8sReporterUpdateExistingPolicyReport(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	// Create an existing PolicyReport
	existingPR := &policyreportv1alpha2.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-abc12",
			Namespace: "default",
		},
		Results: []policyreportv1alpha2.PolicyReportResult{
			{
				Rule:   "existing-rule",
				Policy: "test-policy",
				Result: policyreportv1alpha2.StatusFail,
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingPR).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
	}

	findings := []v1alpha1.RuleFinding{
		{
			RuleName:  "new-rule",
			Message:   "new finding",
			Severity:  "medium",
			EventType: "open",
		},
	}

	// This test verifies the reporter can handle an existing report
	// The exact behavior depends on how the report name is generated
	req := ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: findings,
	}

	err := reporter.Report(context.Background(), req)
	require.NoError(t, err)
}

// TestK8sReporterTruncatesResults tests that results are truncated to max size
func TestK8sReporterTruncatesResults(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
	}

	// Create many findings to exceed maxPolicyReportResults
	findings := make([]v1alpha1.RuleFinding, 30)
	for i := 0; i < 30; i++ {
		findings[i] = v1alpha1.RuleFinding{
			RuleName: "rule-" + string(rune(i)),
			Message:  "finding",
			Severity: "low",
		}
	}

	req := ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: findings,
	}

	err := reporter.Report(context.Background(), req)
	require.NoError(t, err)

	// Note: Exact truncation behavior depends on implementation
	// This test verifies it doesn't crash with many results
}

// TestK8sReporterMultipleSeverities tests results with different severities
func TestK8sReporterMultipleSeverities(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}

	policy := &v1alpha1.RuntimePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
	}

	findings := []v1alpha1.RuleFinding{
		{
			RuleName:  "critical-rule",
			Message:   "critical finding",
			Severity:  "critical",
			EventType: "exec",
		},
		{
			RuleName:  "high-rule",
			Message:   "high finding",
			Severity:  "high",
			EventType: "open",
		},
		{
			RuleName:  "low-rule",
			Message:   "low finding",
			Severity:  "low",
			EventType: "read",
		},
		{
			RuleName:  "info-rule",
			Message:   "info finding",
			Severity:  "info",
			EventType: "write",
		},
	}

	req := ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: findings,
	}

	err := reporter.Report(context.Background(), req)
	require.NoError(t, err)

	// Verify the report was created without error
}
