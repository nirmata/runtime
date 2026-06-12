package lsmmgr

import (
	"fmt"

	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/utils"
	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) rbCreated(compiledRb *compiler.EvaluationResult) error {
	// rb contains no files to ban opening. do nothing with it
	if len(compiledRb.Open) == 0 {
		return nil
	}
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

	_, err = enf.Attach()
	if err != nil {
		return err
	}

	la := &lsmAttachment{
		enf:          enf,
		attachedPods: make(map[string]*podRepresentation),
		selector:     compiledRb.Selector,
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
	return nil
}

func (l *LsmManager) rbUpdated(compiledRb *compiler.EvaluationResult) error {
	// a selector change, or a target change. just compute the diff on the target pods and on the banned files
	la, ok := l.lsmAttachments[compiledRb.UID]
	if !ok {
		return fmt.Errorf("got an update for a runtime behavior that doesn't exist")
	}
	// diff the existing and new files. delete what must be deleted
	// todo: instead of calling this function twice we can call it once and have it return both array
	toAdd := utils.DiffSlice(la.files, compiledRb.Open)
	toRemove := utils.DiffSlice(compiledRb.Open, la.files)

	if len(toAdd) > 0 {
		err := la.enf.AddTargets(toAdd)
		if err != nil {
			return err
		}
	}
	if len(toRemove) > 0 {
		err := la.enf.DeleteTargets(toRemove)
		if err != nil {
			return err
		}
	}

	// set the lsm attachment's file to the incoming compiled rb's open files
	la.files = compiledRb.Open
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
	return nil
}

func (l *LsmManager) rbDeleted(compiledRb *compiler.EvaluationResult) error {
	// delete the pointer from the lsm map
	// and delete it from any pods that may have it
	delete(l.lsmAttachments, compiledRb.UID)
	for _, pod := range l.pods {
		delete(pod.attachedLsms, compiledRb.UID)
	}

	return nil
}
