package pipeline

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	policyreportv1alpha2 "github.com/kyverno/kyverno/api/policyreport/v1alpha2"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
			RuleName:  "new-rule",
			Message:   "new finding",
			Severity:  "medium",
			EventType: "open",
		},
	}

	req := ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: findings,
	}

	err := reporter.Report(context.Background(), req)
	require.NoError(t, err)

	updatedFindings := []v1alpha1.RuleFinding{
		{
			RuleName:  "second-rule",
			Message:   "second finding",
			Severity:  "high",
			EventType: "exec",
		},
	}

	err = reporter.Report(context.Background(), ReportRequest{
		Pod:      pod,
		Policy:   policy,
		Findings: updatedFindings,
	})
	require.NoError(t, err)

	report := &policyreportv1alpha2.PolicyReport{}
	err = c.Get(context.Background(), types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      reportName(pod.Name, policy.Name),
	}, report)
	require.NoError(t, err)
	require.Len(t, report.Results, 2)
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

	// Create enough findings to exceed maxPolicyReportResults
	total := maxPolicyReportResults + 10
	findings := make([]v1alpha1.RuleFinding, total)
	for i := 0; i < total; i++ {
		findings[i] = v1alpha1.RuleFinding{
			RuleName: fmt.Sprintf("rule-%04d", i),
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

	report := &policyreportv1alpha2.PolicyReport{}
	err = c.Get(context.Background(), types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      reportName(pod.Name, policy.Name),
	}, report)
	require.NoError(t, err)
	require.Len(t, report.Results, maxPolicyReportResults)
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

	report := &policyreportv1alpha2.PolicyReport{}
	err = c.Get(context.Background(), types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      reportName(pod.Name, policy.Name),
	}, report)
	require.NoError(t, err)
	require.Equal(t, 2, report.Summary.Warn)
	require.Equal(t, 2, report.Summary.Fail)
	for _, result := range report.Results {
		require.NotEmpty(t, result.Properties[propertyFingerprint])
		require.Equal(t, "1", result.Properties[propertyCount])
		require.NotEmpty(t, result.Properties[propertyFirstSeen])
		require.NotEmpty(t, result.Properties[propertyLastSeen])
	}
	// Verify the report was created without error
}

func TestK8sReporterDeduplicatesByFingerprint(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dedup-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}
	policy := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy"}}

	baseFinding := v1alpha1.RuleFinding{
		RuleName:  "rule-open-hosts",
		Message:   "opened sensitive file",
		Severity:  "high",
		EventType: "open",
		Fields: map[string]string{
			"fname":          "/etc/hosts",
			"container.name": "main",
		},
	}

	err := reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{baseFinding}})
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)
	err = reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{baseFinding}})
	require.NoError(t, err)

	report := &policyreportv1alpha2.PolicyReport{}
	err = c.Get(context.Background(), types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      reportName(pod.Name, policy.Name),
	}, report)
	require.NoError(t, err)
	require.Len(t, report.Results, 1)

	result := report.Results[0]
	require.Equal(t, "2", result.Properties[propertyCount])
	require.NotEmpty(t, result.Properties[propertyFingerprint])

	firstSeen := parseRFC3339Property(t, result.Properties[propertyFirstSeen])
	lastSeen := parseRFC3339Property(t, result.Properties[propertyLastSeen])
	require.True(t, lastSeen.After(firstSeen) || lastSeen.Equal(firstSeen))
	require.Equal(t, firstSeen.Format(time.RFC3339), result.Properties[propertyFirstSeen])
	require.Equal(t, lastSeen.Format(time.RFC3339), result.Properties[propertyLastSeen])
}

func TestK8sReporterDifferentMatchedFieldsCreateDifferentResults(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporter(c)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dedup-pod",
			Namespace: "default",
			UID:       "12345",
		},
	}
	policy := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy"}}

	first := v1alpha1.RuleFinding{
		RuleName:  "rule-open-sensitive",
		Message:   "opened file",
		Severity:  "high",
		EventType: "open",
		Fields: map[string]string{
			"fname":          "/etc/hosts",
			"container.name": "main",
		},
	}
	second := v1alpha1.RuleFinding{
		RuleName:  "rule-open-sensitive",
		Message:   "opened file",
		Severity:  "high",
		EventType: "open",
		Fields: map[string]string{
			"fname":          "/etc/passwd",
			"container.name": "main",
		},
	}

	err := reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{first}})
	require.NoError(t, err)
	err = reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{second}})
	require.NoError(t, err)

	report := &policyreportv1alpha2.PolicyReport{}
	err = c.Get(context.Background(), types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      reportName(pod.Name, policy.Name),
	}, report)
	require.NoError(t, err)
	require.Len(t, report.Results, 2)

	for _, result := range report.Results {
		count, err := strconv.Atoi(result.Properties[propertyCount])
		require.NoError(t, err)
		require.Equal(t, 1, count)
	}

	// Verify the report was created without error
}

func TestK8sReporterBufferedFlushByMaxCount(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporterWithOptions(c, ReporterOptions{BufferInterval: time.Hour, MaxBufferedCount: 2})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "buffer-pod", Namespace: "default", UID: "12345"}}
	policy := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy"}}
	finding := v1alpha1.RuleFinding{
		RuleName:  "rule-open-hosts",
		Message:   "opened sensitive file",
		Severity:  "high",
		EventType: "open",
		Fields: map[string]string{
			"fname":          "/etc/hosts",
			"container.name": "main",
		},
	}

	err := reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{finding}})
	require.NoError(t, err)

	report := &policyreportv1alpha2.PolicyReport{}
	err = c.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: reportName(pod.Name, policy.Name)}, report)
	require.Error(t, err)

	err = reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{finding}})
	require.NoError(t, err)

	err = c.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: reportName(pod.Name, policy.Name)}, report)
	require.NoError(t, err)
	require.Len(t, report.Results, 1)
	require.Equal(t, "2", report.Results[0].Properties[propertyCount])
}

func TestK8sReporterBufferedFlushByInterval(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyreportv1alpha2.Install(scheme))

	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	reporter := NewK8sReporterWithOptions(c, ReporterOptions{BufferInterval: 150 * time.Millisecond, MaxBufferedCount: 1000})

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "buffer-timer-pod", Namespace: "default", UID: "12345"}}
	policy := &v1alpha1.RuntimePolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy"}}
	finding := v1alpha1.RuleFinding{RuleName: "rule", Message: "msg", Severity: "high", EventType: "exec"}

	err := reporter.Report(context.Background(), ReportRequest{Pod: pod, Policy: policy, Findings: []v1alpha1.RuleFinding{finding}})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		report := &policyreportv1alpha2.PolicyReport{}
		err := c.Get(context.Background(), types.NamespacedName{Namespace: pod.Namespace, Name: reportName(pod.Name, policy.Name)}, report)
		return err == nil && len(report.Results) == 1
	}, 3*time.Second, 100*time.Millisecond)
}

func parseRFC3339Property(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	require.NoError(t, err)
	return parsed
}
