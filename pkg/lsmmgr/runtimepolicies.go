package lsmmgr

import (
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) rpCreated(compiledRp *compiler.EvaluationResult) error {
	l.logger.V(2).Info("runtime policy created", "uid", compiledRp.UID)
	if compiledRp.Mode != "enforce" {
		return nil
	}

	var (
		openEnforcer *lsm.LsmEnforcer
		execEnforcer *lsm.LsmEnforcer
		err          error
	)

	if compiledRp.Open.HasEntries() {
		openEnforcer, err = l.createForProgType(compiledRp.Open, lsm.PROG_TYPE_LSM_OPEN)
		if err != nil {
			return err
		}
	}

	if compiledRp.Exec.HasEntries() {
		execEnforcer, err = l.createForProgType(compiledRp.Exec, lsm.PROG_TYPE_LSM_EXEC)
		if err != nil {
			return err
		}
	}

	if openEnforcer == nil && execEnforcer == nil {
		l.logger.V(2).Info("runtime policy created but has no open or exec entries", "uid", compiledRp.UID)
		return nil
	}

	la := &lsmAttachment{
		openEnforcer: openEnforcer,
		execEnforcer: execEnforcer,
		attachedPods: make(map[string]*podRepresentation),
		selector:     compiledRp.Selector,
		openFiles:    compiledRp.Open,
		execFiles:    compiledRp.Exec,
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
	// no target pods matched the runtime policy
	if len(targetCgids) == 0 {
		return nil
	}

	if openEnforcer != nil {
		openEnforcer.AddCgids(targetCgids)
	}

	if execEnforcer != nil {
		execEnforcer.AddCgids(targetCgids)
	}

	return nil
}

func (l *LsmManager) rpUpdated(compiledRp *compiler.EvaluationResult) error {
	l.logger.V(2).Info("runtime policy updated", "uid", compiledRp.UID)
	if compiledRp.Mode != "enforce" {
		l.rpDeleted(compiledRp)
		return nil
	}
	// a selector change, or a target change. just compute the diff on the target pods and on the banned files
	la, ok := l.lsmAttachments[compiledRp.UID]
	if !ok {
		// no existing attachment. if the update introduced open targets, this is the first
		// time the policy needs enforcement, so run it through the creation path.
		if !compiledRp.Open.HasEntries() && !compiledRp.Exec.HasEntries() {
			l.logger.V(2).Info("runtime policy update has no open files to enforce and no existing attachment, skipping", "uid", compiledRp.UID)
			return nil
		}
		l.logger.V(2).Info("runtime policy update introduced open targets for a previously unattached policy, creating attachment", "uid", compiledRp.UID)
		return l.rpCreated(compiledRp)
	}

	la.selector = compiledRp.Selector
	err := l.syncProgType(compiledRp.UID, la, compiledRp.Open, lsm.PROG_TYPE_LSM_OPEN)
	if err != nil {
		return err
	}

	err = l.syncProgType(compiledRp.UID, la, compiledRp.Exec, lsm.PROG_TYPE_LSM_EXEC)
	if err != nil {
		return err
	}

	// now that we run sync pod attachment once and inside it we check that both enforcers aren't nil
	// previous member ship should be denoted by having an entry for a given pod and new membership
	// should be denoted by compiledrp.selector.matches
	l.syncPodAttachment(compiledRp.UID, la)
	return nil
}

func (l *LsmManager) rpDeleted(compiledRp *compiler.EvaluationResult) {
	l.logger.V(2).Info("runtime policy deleted", "uid", compiledRp.UID)
	// delete the pointer from the lsm map
	// and delete it from any pods that may have it
	delete(l.lsmAttachments, compiledRp.UID)
	for _, pod := range l.pods {
		delete(pod.attachedLsms, compiledRp.UID)
	}
}

func (l *LsmManager) createForProgType(pair *compiler.AllowDenyPair, progType string) (*lsm.LsmEnforcer, error) {
	// create the lsm enforcer
	enf, err := lsm.NewForAttachTarget(&l.logger, progType)
	if err != nil {
		return nil, err
	}

	// add targets
	err = enf.AddTargets(pair)
	if err != nil {
		return nil, err
	}

	// set default deny if the compiled policy had the * in its list of files
	defaultDeny := slices.Contains(pair.Deny, "*")
	if err := enf.SetDefaultDeny(defaultDeny); err != nil {
		return nil, err
	}

	_, err = enf.Attach()
	if err != nil {
		return nil, err
	}

	return enf, nil
}

func (l *LsmManager) syncProgType(uid string, la *lsmAttachment, newFiles *compiler.AllowDenyPair, progType string) error {
	enf, filesPtr := la.access(progType)
	oldFiles := *filesPtr

	var toAddPair, toRemovePair *compiler.AllowDenyPair
	if oldFiles != nil {
		toAddPair = oldFiles.DiffPair(newFiles)
		toRemovePair = newFiles.DiffPair(oldFiles)
	} else {
		toAddPair = newFiles
	}

	hasFileChanges := (toAddPair != nil && toAddPair.HasEntries()) || (toRemovePair != nil && toRemovePair.HasEntries())

	if hasFileChanges {
		if *enf == nil {
			err := l.initEnforcer(uid, la, enf, newFiles, progType)
			if err != nil {
				return err
			}
		} else {
			if toAddPair != nil && toAddPair.HasEntries() {
				if err := (*enf).AddTargets(toAddPair); err != nil {
					return err
				}
			}
			if toRemovePair != nil && toRemovePair.HasEntries() {
				if err := (*enf).DeleteTargets(toRemovePair); err != nil {
					return err
				}
			}
			defaultDeny := slices.Contains(newFiles.Deny, "*")
			if err := (*enf).SetDefaultDeny(defaultDeny); err != nil {
				return err
			}
		}
	}

	*filesPtr = newFiles
	return nil
}

func (l *LsmManager) initEnforcer(uid string, la *lsmAttachment, enf **lsm.LsmEnforcer, newFiles *compiler.AllowDenyPair, progType string) error {
	newEnf, err := lsm.NewForAttachTarget(&l.logger, progType)
	if err != nil {
		return err
	}
	if err := newEnf.AddTargets(newFiles); err != nil {
		return err
	}
	defaultDeny := slices.Contains(newFiles.Deny, "*")
	if err := newEnf.SetDefaultDeny(defaultDeny); err != nil {
		return err
	}
	if _, err := newEnf.Attach(); err != nil {
		return err
	}
	// backfill cgids for pods that were already attached to this policy
	for _, pod := range la.attachedPods {
		newEnf.AddCgids(pod.cgids)
	}
	*enf = newEnf
	return nil
}

func (l *LsmManager) syncPodAttachment(uid string, la *lsmAttachment) {
	for podUid, pod := range l.pods {
		// there is an implicit assumption here that la.selector contains the new selector from the update.
		// if this is no longer the case, the function will be using the old selctor to check if we should
		// still match a given pod or no
		if la.selector.Matches(labels.Set(pod.labels)) {
			_, ok := la.attachedPods[podUid]
			if ok {
				// we are already attached to this pod cgid. nothing to do
				continue
			}
			// we aren't attached
			l.logger.V(2).Info("newly matched pod for runtime policy, adding cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
			if la.openEnforcer != nil {
				la.openEnforcer.AddCgids(pod.cgids)
			}

			if la.execEnforcer != nil {
				la.execEnforcer.AddCgids(pod.cgids)
			}
			la.attachedPods[podUid] = pod
		} else {
			// we don't match that pod. did we previously match it ?
			_, ok := la.attachedPods[podUid]
			if ok {
				// yes we did. remove its cgids from the enforcer before dropping the attachment
				l.logger.V(2).Info("pod no longer matches runtime policy, removing cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
				if la.openEnforcer != nil {
					la.openEnforcer.DeleteCgids(pod.cgids)
				}

				if la.execEnforcer != nil {
					la.execEnforcer.DeleteCgids(pod.cgids)
				}
				delete(la.attachedPods, podUid)
			}
		}
	}
}
