package controller

import (
	"context"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type DaemonPlacement struct {
	namespace  string
	name       string
	daemonSets cache.SharedIndexInformer
	pods       cache.SharedIndexInformer
	nodes      cache.SharedIndexInformer
	onChange   func()
}

func NewDaemonPlacement(client kubernetes.Interface, namespace, name string,
	nodes cache.SharedIndexInformer, onChange func()) (*DaemonPlacement, error) {
	dsFactory := informers.NewSharedInformerFactoryWithOptions(client, 0,
		informers.WithNamespace(namespace), informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
		}))
	podFactory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(namespace))
	p := &DaemonPlacement{
		namespace: namespace, name: name, nodes: nodes, onChange: onChange,
		daemonSets: dsFactory.Apps().V1().DaemonSets().Informer(),
		pods:       podFactory.Core().V1().Pods().Informer(),
	}
	if err := p.daemonSets.SetTransform(func(obj any) (any, error) {
		if ds, ok := obj.(*appsv1.DaemonSet); ok {
			return &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: ds.Name, Namespace: ds.Namespace, UID: ds.UID,
					Generation: ds.Generation, DeletionTimestamp: ds.DeletionTimestamp},
				Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: ds.Status.DesiredNumberScheduled,
					ObservedGeneration: ds.Status.ObservedGeneration},
			}, nil
		}
		return obj, nil
	}); err != nil {
		return nil, err
	}
	if err := p.pods.SetTransform(func(obj any) (any, error) {
		if pod, ok := obj.(*corev1.Pod); ok {
			return &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: pod.Name, Namespace: pod.Namespace, UID: pod.UID,
					OwnerReferences: pod.OwnerReferences, DeletionTimestamp: pod.DeletionTimestamp,
				},
				Spec:   corev1.PodSpec{NodeName: pod.Spec.NodeName, Affinity: pod.Spec.Affinity},
				Status: corev1.PodStatus{Phase: pod.Status.Phase},
			}, nil
		}
		return obj, nil
	}); err != nil {
		return nil, err
	}
	changed := func(obj any) {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			obj = tombstone.Obj
		}
		if pod, ok := obj.(*corev1.Pod); ok {
			owner := metav1.GetControllerOf(pod)
			if owner == nil || owner.Kind != "DaemonSet" || owner.Name != name {
				return
			}
		}
		onChange()
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: changed, DeleteFunc: changed,
		UpdateFunc: func(old, cur any) {
			if !apiequality.Semantic.DeepEqual(old, cur) {
				changed(old)
				changed(cur)
			}
		},
	}
	for _, informer := range []cache.SharedIndexInformer{p.daemonSets, p.pods, nodes} {
		if _, err := informer.AddEventHandler(handler); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *DaemonPlacement) Run(ctx context.Context) error {
	go p.daemonSets.Run(ctx.Done())
	go p.pods.Run(ctx.Done())
	if cache.WaitForCacheSync(ctx.Done(), p.daemonSets.HasSynced, p.pods.HasSynced, p.nodes.HasSynced) {
		p.onChange()
	}
	<-ctx.Done()
	return nil
}

func (p *DaemonPlacement) Snapshot() ExpectedSourceNodes {
	if !p.daemonSets.HasSynced() || !p.pods.HasSynced() || !p.nodes.HasSynced() {
		return ExpectedSourceNodes{}
	}
	obj, exists, err := p.daemonSets.GetStore().GetByKey(p.namespace + "/" + p.name)
	if err != nil || !exists {
		return ExpectedSourceNodes{}
	}
	ds, ok := obj.(*appsv1.DaemonSet)
	if !ok {
		return ExpectedSourceNodes{}
	}
	var pods []*corev1.Pod
	for _, obj := range p.pods.GetStore().List() {
		if pod, ok := obj.(*corev1.Pod); ok {
			pods = append(pods, pod)
		}
	}
	return daemonPlacementNodes(ds, pods, func(name string) bool {
		_, exists, err := p.nodes.GetStore().GetByKey(name)
		return err == nil && exists
	})
}

func daemonPlacementNodes(ds *appsv1.DaemonSet, pods []*corev1.Pod, nodeExists func(string) bool) ExpectedSourceNodes {
	result := ExpectedSourceNodes{
		Desired: int(ds.Status.DesiredNumberScheduled),
		Synced:  ds.Status.ObservedGeneration >= ds.Generation && ds.DeletionTimestamp == nil,
	}
	names := make(map[string]struct{})
	for _, pod := range pods {
		owner := metav1.GetControllerOf(pod)
		if owner == nil || owner.UID != ds.UID || owner.Kind != "DaemonSet" ||
			pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if name := daemonPodNodeName(pod); name != "" && nodeExists(name) {
			names[name] = struct{}{}
		}
	}
	for name := range names {
		result.Names = append(result.Names, name)
	}
	sort.Strings(result.Names)
	return result
}

func daemonPodNodeName(pod *corev1.Pod) string {
	if pod.Spec.NodeName != "" {
		return pod.Spec.NodeName
	}
	affinity := pod.Spec.Affinity
	if affinity == nil || affinity.NodeAffinity == nil || affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return ""
	}
	// DaemonSet pods name their target in required affinity before the scheduler
	// binds them. An ambiguous selector is not evidence of one expected node.
	var target string
	for _, term := range affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
		var name string
		for _, field := range term.MatchFields {
			if field.Key == "metadata.name" && field.Operator == corev1.NodeSelectorOpIn && len(field.Values) == 1 {
				name = field.Values[0]
			}
		}
		if name == "" || (target != "" && target != name) {
			return ""
		}
		target = name
	}
	return target
}
