package lsmmgr

import (
	"fmt"

	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"k8s.io/apimachinery/pkg/labels"
)

// i will assume exec doesn't exist for now
type LsmManager struct {
	pods           map[string]*podRepresentation // pod label storage. todo: take this out of here
	lsmAttachments map[string]*lsmAttachment
}

type podRepresentation struct {
	cgids  []uint64 // todo: we don't need the cgroup path and are only storing the cgid here. we need to have an extraction mechanism
	labels map[string]string
}

type lsmAttachment struct {
	enf          *lsm.LsmEnforcer
	attachedPods map[string]*podRepresentation
	files        []string
}

func NewLsmManager() *LsmManager {
	return &LsmManager{}
}

func (l *LsmManager) RuntimeBehaviorEvent(compiledRb *compiler.EvaluationResult, eventType string) error {
	switch eventType {
	case "create":
		// create the lsm enforcer
		enf, err := lsm.NewForAttachTarget(&logr.Logger{}, "file_open")
		if err != nil {
			return err
		}
		// add the banned files
		err = enf.AddTargets(compiledRb.Open)
		if err != nil {
			return err
		}
		la := &lsmAttachment{
			enf:          enf,
			attachedPods: make(map[string]*podRepresentation),
		}
		// set the target pods (cgid)
		targetCgids := []uint64{}
		for podUid, pod := range l.pods {
			if compiledRb.Selector.Matches(labels.Set(pod.labels)) {
				// add a pointer to this attached pod
				la.attachedPods[podUid] = pod
				targetCgids = append(targetCgids, pod.cgids...)
			}
			err := enf.AddCgids(targetCgids)
			if err != nil {
				// todo: handle this
				continue
			}
		}

		l.lsmAttachments[compiledRb.UID] = la
	case "update":
		// a selector change, or a target change. just compute the diff on the target pods and on the banned files
		la, ok := l.lsmAttachments[compiledRb.UID]
		if !ok {
			return fmt.Errorf("got an update for a runtime behavior that doesn't exist")
		}
		// diff the existing and new files. delete what must be deleted

		for podUid, pod := range l.pods {
			if compiledRb.Selector.Matches(labels.Set(pod.labels)) {
				_, ok := la.attachedPods[podUid]
				if ok {
					// we are already attached to this pod cgid. nothing to do
					continue
				}
				// we aren't attached
				err := la.enf.AddCgids(pod.cgids)
				if err != nil {
					continue
				}
			} else {
				// we don't match that pod. did we previously match it ?
				_, ok := la.attachedPods[podUid]
				if ok {
					// yes we did
					delete(la.attachedPods, podUid)
					continue
				}
			}
		}
	case "delete":
		// does deletion of a link.link automatically detach it ?
	}
	return nil
}

// return the entries in array b and not a
func diffSlice(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	var out []string
	for _, v := range b {
		if _, ok := set[v]; !ok {
			out = append(out, v)
		}
	}
	return out
}
