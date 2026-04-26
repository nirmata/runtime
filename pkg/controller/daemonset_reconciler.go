package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/nirmata/kyverno-runtime/api/v1alpha1"
	"github.com/nirmata/kyverno-runtime/pkg/pipeline"
)

// DaemonSetReconciler watches Pods and keeps streaming eBPF watches in sync
// with the set of matching RuntimePolicies. Actual event collection, evaluation,
// and reporting happen inside the WatchManager — not on the reconcile path.
type DaemonSetReconciler struct {
	client       client.Client
	matcher      pipeline.Matcher
	watchManager *pipeline.WatchManager
	enrollment   RuntimeBehaviorEnrollmentConfig
	nodeName     string
}

// RuntimeBehaviorEnrollmentConfig controls auto-creation of RuntimeBehavior profiles.
type RuntimeBehaviorEnrollmentConfig struct {
	AutoCreate              bool
	IncludeControllers      map[string]bool
	IncludeBarePods         bool
	IncludeNamespaces       map[string]bool
	ExcludeNamespaces       map[string]bool
	InitialMode             v1alpha1.RuntimeBehaviorMode
	OptOutLabel             string
	SharedDefaultsNamespace string
}

func DefaultRuntimeBehaviorEnrollmentConfig() RuntimeBehaviorEnrollmentConfig {
	return RuntimeBehaviorEnrollmentConfig{
		AutoCreate: false,
		IncludeControllers: map[string]bool{
			"Deployment":  true,
			"StatefulSet": true,
			"DaemonSet":   true,
			"Job":         true,
			"CronJob":     true,
			"ReplicaSet":  true,
		},
		IncludeBarePods:         false,
		IncludeNamespaces:       map[string]bool{},
		ExcludeNamespaces:       map[string]bool{"kube-system": true, "kyverno-runtime": true},
		InitialMode:             v1alpha1.ModeLearning,
		OptOutLabel:             "",
		SharedDefaultsNamespace: "kyverno-runtime",
	}
}

// NewDaemonSetReconciler creates a new DaemonSetReconciler.
func NewDaemonSetReconciler(
	c client.Client,
	matcher pipeline.Matcher,
	watchManager *pipeline.WatchManager,
) *DaemonSetReconciler {
	return NewDaemonSetReconcilerWithEnrollmentConfig(c, matcher, watchManager, DefaultRuntimeBehaviorEnrollmentConfig())
}

// NewDaemonSetReconcilerWithEnrollmentConfig creates a new DaemonSetReconciler
// with RuntimeBehavior enrollment controls.
func NewDaemonSetReconcilerWithEnrollmentConfig(
	c client.Client,
	matcher pipeline.Matcher,
	watchManager *pipeline.WatchManager,
	enrollment RuntimeBehaviorEnrollmentConfig,
) *DaemonSetReconciler {
	return &DaemonSetReconciler{
		client:       c,
		matcher:      matcher,
		watchManager: watchManager,
		enrollment:   enrollment,
	}
}

// SetNodeName configures the local node name used for node-local pod filtering.
func (r *DaemonSetReconciler) SetNodeName(nodeName string) {
	r.nodeName = strings.TrimSpace(nodeName)
}

// Reconcile syncs the streaming watch state for a Pod. It is called whenever
// a Pod or RuntimePolicy changes. It does not collect events directly.
func (r *DaemonSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Get the pod.
	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			// Pod gone — WatchManager cleans up via context cancellation when
			// the controller-runtime context is cancelled or next sync.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Only watch Running pods; skip pods that are terminating or not yet scheduled.
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		r.watchManager.StopPod(pod)
		return ctrl.Result{}, nil
	}
	if r.nodeName != "" && strings.TrimSpace(pod.Spec.NodeName) != "" && pod.Spec.NodeName != r.nodeName {
		// In node-local mode, proactively stop any existing watch for off-node pods.
		r.watchManager.StopPod(pod)
		return ctrl.Result{}, nil
	}

	if err := r.ensureRuntimeBehaviorForPod(ctx, pod); err != nil {
		return ctrl.Result{}, err
	}

	// Get the namespace to access labels for policy matching.
	ns := &corev1.Namespace{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: pod.Namespace}, ns); err != nil {
		return ctrl.Result{}, err
	}

	// List all RuntimePolicies and find those matching this pod.
	policies := &v1alpha1.RuntimePolicyList{}
	if err := r.client.List(ctx, policies); err != nil {
		return ctrl.Result{}, err
	}

	matched := make([]*v1alpha1.RuntimePolicy, 0)
	for i := range policies.Items {
		p := &policies.Items[i]
		ok, err := r.matcher.Matches(p, pod, ns.Labels)
		if err != nil {
			return ctrl.Result{}, err
		}
		if ok {
			matched = append(matched, p)
		}
	}

	// Sync streaming watches — start for matched policies, stop if none match.
	r.watchManager.Sync(ctx, pod, matched)
	return ctrl.Result{}, nil
}

func (r *DaemonSetReconciler) ensureRuntimeBehaviorForPod(ctx context.Context, pod *corev1.Pod) error {
	if !r.enrollment.AutoCreate {
		return nil
	}
	if !r.isEligibleForEnrollment(pod) {
		return nil
	}

	refs, err := r.discoverSharedDefaults(ctx, pod)
	if err != nil {
		return err
	}

	existing := &v1alpha1.RuntimeBehaviorList{}
	if err := r.client.List(ctx, existing, client.InNamespace(pod.Namespace)); err != nil {
		return err
	}
	for i := range existing.Items {
		rb := &existing.Items[i]
		if rb.Labels == nil {
			continue
		}
		if rb.Labels["runtime.kyverno.io/managed"] == "true" && rb.Labels["runtime.kyverno.io/workload-pod"] == pod.Name {
			if !behaviorRefsEqual(rb.Spec.Allow, refs) {
				updated := rb.DeepCopyObject().(*v1alpha1.RuntimeBehavior)
				if updated.Spec.Allow == nil {
					updated.Spec.Allow = &v1alpha1.AllowRules{}
				}
				updated.Spec.Allow.Refs = refs
				if err := r.client.Update(ctx, updated); err != nil {
					return err
				}
			}
			return nil
		}
	}

	now := metav1.NewTime(time.Now().UTC())
	selector := map[string]string{}
	if app := strings.TrimSpace(pod.Labels["app"]); app != "" {
		selector["app"] = app
	} else {
		selector["runtime.kyverno.io/workload-pod"] = pod.Name
	}
	if runtimeClass := strings.TrimSpace(pod.Labels["runtime.kyverno.io/runtime-class"]); runtimeClass != "" {
		selector["runtime.kyverno.io/runtime-class"] = runtimeClass
	}

	rb := &v1alpha1.RuntimeBehavior{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("auto-%s-%s", pod.Name, shortUID(string(pod.UID))),
			Namespace: pod.Namespace,
			Labels: map[string]string{
				"runtime.kyverno.io/managed":      "true",
				"runtime.kyverno.io/workload-pod": pod.Name,
			},
		},
		Spec: v1alpha1.RuntimeBehaviorSpec{
			WorkloadSelector: &metav1.LabelSelector{MatchLabels: selector},
			Mode:             r.enrollment.InitialMode,
			Learning: &v1alpha1.LearningConfig{
				Duration:   &metav1.Duration{Duration: 24 * time.Hour},
				MinSamples: 100,
				StartAfter: v1alpha1.StartAfterReady,
			},
			Allow: &v1alpha1.AllowRules{Refs: refs},
		},
		Status: v1alpha1.RuntimeBehaviorStatus{
			Lifecycle:          v1alpha1.LifecycleLearning,
			LastTransitionTime: &now,
			Confidence: &v1alpha1.ConfidenceMetadata{
				ObservedFrom: &now,
				ObservedTo:   &now,
				SampleCount:  0,
				DropRate:     0,
			},
		},
	}

	if err := r.client.Create(ctx, rb); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (r *DaemonSetReconciler) isEligibleForEnrollment(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	if r.enrollment.ExcludeNamespaces[pod.Namespace] {
		return false
	}
	if len(r.enrollment.IncludeNamespaces) > 0 && !r.enrollment.IncludeNamespaces[pod.Namespace] {
		return false
	}
	if key := strings.TrimSpace(r.enrollment.OptOutLabel); key != "" {
		v := strings.ToLower(strings.TrimSpace(pod.Labels[key]))
		if v == "true" || v == "1" || v == "yes" {
			return false
		}
	}

	ownerKind := ""
	if len(pod.OwnerReferences) > 0 {
		ownerKind = pod.OwnerReferences[0].Kind
	}
	if ownerKind == "" {
		return r.enrollment.IncludeBarePods
	}
	return r.enrollment.IncludeControllers[ownerKind]
}

func (r *DaemonSetReconciler) discoverSharedDefaults(ctx context.Context, pod *corev1.Pod) ([]v1alpha1.BehaviorReference, error) {
	ns := r.enrollment.SharedDefaultsNamespace
	if strings.TrimSpace(ns) == "" {
		ns = "kyverno-runtime"
	}
	list := &v1alpha1.RuntimeBehaviorList{}
	if err := r.client.List(ctx, list, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	runtimeClass := strings.TrimSpace(pod.Labels["runtime.kyverno.io/runtime-class"])

	refs := make([]v1alpha1.BehaviorReference, 0)
	for i := range list.Items {
		rb := &list.Items[i]
		if rb.Spec.WorkloadSelector != nil {
			continue
		}
		if rb.Labels["scope"] == "all" {
			refs = append(refs, v1alpha1.BehaviorReference{Name: rb.Name, Namespace: rb.Namespace})
			continue
		}
		class := strings.TrimSpace(rb.Labels["runtime.kyverno.io/runtime-class"])
		switch {
		case class == "":
			refs = append(refs, v1alpha1.BehaviorReference{Name: rb.Name, Namespace: rb.Namespace})
		case runtimeClass != "" && class == runtimeClass:
			refs = append(refs, v1alpha1.BehaviorReference{Name: rb.Name, Namespace: rb.Namespace})
		}
	}

	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Namespace != refs[j].Namespace {
			return refs[i].Namespace < refs[j].Namespace
		}
		return refs[i].Name < refs[j].Name
	})
	return refs, nil
}

func behaviorRefsEqual(allow *v1alpha1.AllowRules, expected []v1alpha1.BehaviorReference) bool {
	if allow == nil {
		return len(expected) == 0
	}
	if len(allow.Refs) != len(expected) {
		return false
	}
	for i := range allow.Refs {
		if allow.Refs[i].Name != expected[i].Name || allow.Refs[i].Namespace != expected[i].Namespace {
			return false
		}
	}
	return true
}

func shortUID(uid string) string {
	if len(uid) <= 8 {
		return uid
	}
	return uid[:8]
}
