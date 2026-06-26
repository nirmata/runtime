package lsmmgr

import (
	"fmt"

	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/utils"
	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) rpCreated(compiledRp *compiler.EvaluationResult) error {
	// rp contains no files to ban opening. do nothing with it
	if len(compiledRp.Open.Allow) == 0 && len(compiledRp.Open.Deny) == 0 {
		return nil
	}
	// create the lsm enforcer
	enf, err := lsm.NewForAttachTarget(&logr.Logger{}, "file_open")
	if err != nil {
		return err
	}
	// add the banned files
	err = enf.AddTargets(compiledRp.Open)
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
		selector:     compiledRp.Selector,
	}
	l.lsmAttachments[compiledRp.UID] = la
	// set the target pods (cgid)
	targetCgids := []uint64{}
	for podUid, pod := range l.pods {
		if compiledRp.Selector.Matches(labels.Set(pod.labels)) {
			// add a pointer to this attached pod
			la.attachedPods[podUid] = pod
			targetCgids = append(targetCgids, pod.cgids...)
		}

	}
	if len(targetCgids) > 0 {
		err := enf.AddCgids(targetCgids)
		if err != nil {
			// todo: handle this
			return err
		}
	}
	return nil
}

func (l *LsmManager) rpUpdated(compiledRp *compiler.EvaluationResult) error {
	// a selector change, or a target change. just compute the diff on the target pods and on the banned files
	la, ok := l.lsmAttachments[compiledRp.UID]
	if !ok {
		return fmt.Errorf("got an update for a runtime behavior that doesn't exist")
	}
	// diff the existing and new files. delete what must be deleted
	// todo: instead of calling this function twice we can call it once and have it return both array
	toAddAllow := utils.DiffSlice(la.files.Allow, compiledRp.Open.Allow)
	toRemoveAllow := utils.DiffSlice(compiledRp.Open.Allow, la.files.Allow)

	toAddDeny := utils.DiffSlice(la.files.Deny, compiledRp.Open.Deny)
	toRemoveDeny := utils.DiffSlice(compiledRp.Open.Deny, la.files.Deny)

	if len(toAddAllow) > 0 || len(toAddDeny) > 0 {
		err := la.enf.AddTargets(&compiler.AllowDenyPair{Allow: toAddAllow, Deny: toAddDeny})
		if err != nil {
			return err
		}
	}
	if len(toRemoveAllow) > 0 || len(toRemoveDeny) > 0 {
		err := la.enf.DeleteTargets(&compiler.AllowDenyPair{Allow: toRemoveAllow, Deny: toAddDeny})
		if err != nil {
			return err
		}
	}

	// set the lsm attachment's file to the incoming compiled rp's open files
	la.files = compiledRp.Open
	for podUid, pod := range l.pods {
		if compiledRp.Selector.Matches(labels.Set(pod.labels)) {
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

func (l *LsmManager) rpDeleted(compiledRp *compiler.EvaluationResult) error {
	// delete the pointer from the lsm map
	// and delete it from any pods that may have it
	delete(l.lsmAttachments, compiledRp.UID)
	for _, pod := range l.pods {
		delete(pod.attachedLsms, compiledRp.UID)
	}

	return nil
}
