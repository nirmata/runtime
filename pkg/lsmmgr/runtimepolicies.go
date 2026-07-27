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
		progMap      = make(map[string]*progState)
		err          error
	)

	if compiledRp.Open.HasEntries() {
		openEnforcer, err = l.createForProgType(compiledRp.Open, lsm.PROG_TYPE_LSM_OPEN)
		if err != nil {
			return err
		}

		progMap[lsm.PROG_TYPE_LSM_OPEN] = &progState{
			files: compiledRp.Open,
			enf:   openEnforcer,
		}
	}

	if compiledRp.Exec.HasEntries() {
		execEnforcer, err = l.createForProgType(compiledRp.Exec, lsm.PROG_TYPE_LSM_EXEC)
		if err != nil {
			return err
		}

		progMap[lsm.PROG_TYPE_LSM_EXEC] = &progState{
			files: compiledRp.Exec,
			enf:   execEnforcer,
		}
	}

	if openEnforcer == nil && execEnforcer == nil {
		l.logger.V(2).Info("runtime policy created but has no open or exec entries", "uid", compiledRp.UID)
		return nil
	}

	la := &lsmAttachment{
		progs:        progMap,
		attachedPods: make(map[string]*podRepresentation),
		selector:     compiledRp.Selector,
	}
	l.lsmAttachments[compiledRp.UID] = la

	// set the target pods (cgid)
	targetCgids := []uint64{}
	for podUid, pod := range l.pods {
		if compiledRp.Selector.Matches(labels.Set(pod.labels)) {
			// add a pointer to this attached pod
			attach(compiledRp.UID, la, podUid, pod)
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
	err := l.syncProgType(la, compiledRp.Open, lsm.PROG_TYPE_LSM_OPEN)
	if err != nil {
		return err
	}

	err = l.syncProgType(la, compiledRp.Exec, lsm.PROG_TYPE_LSM_EXEC)
	if err != nil {
		return err
	}

	l.syncPodAttachment(compiledRp.UID, la)
	return nil
}

func (l *LsmManager) rpDeleted(compiledRp *compiler.EvaluationResult) {
	la, ok := l.lsmAttachments[compiledRp.UID]
	if !ok {
		return
	}
	for _, prog := range la.progs {
		if err := prog.enf.Close(); err != nil {
			l.logger.Error(err, "failed to close bpf lsm enforcer")
		}
	}
	// delete the pointer from the lsm map
	// and delete it from any pods that may have it
	delete(l.lsmAttachments, compiledRp.UID)
	for _, pod := range l.pods {
		delete(pod.attachedLsms, compiledRp.UID)
	}
}

func (l *LsmManager) createForProgType(pair *compiler.AllowDenyPair, progType string) (*lsm.LsmEnforcer, error) {
	// create the lsm enforcer
	cleanup := false
	enf, err := lsm.NewForAttachTarget(&l.logger, progType)
	if err != nil {
		return nil, err
	}

	defer func() {
		if cleanup {
			if err := enf.Close(); err != nil {
				l.logger.Error(err, "failed to cleanup lsm enforcer on error")
			}
		}
	}()
	cleanup = true

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
	cleanup = false
	return enf, nil
}

func (l *LsmManager) syncProgType(la *lsmAttachment, newFiles *compiler.AllowDenyPair, progType string) error {
	prog, ok := la.progs[progType]
	if !ok {
		// we are syncing a program type we didn't have an enforcer loaded for before
		// but there aren't any files. we can just ignore that
		if !newFiles.HasEntries() {
			return nil
		}

		enforcer, err := l.createForProgType(newFiles, progType)
		if err != nil {
			return err
		}
		for _, pod := range la.attachedPods {
			enforcer.AddCgids(pod.cgids)
		}

		ps := &progState{
			enf:   enforcer,
			files: newFiles,
		}

		la.progs[progType] = ps
		prog = ps
	}

	// the newfiles specify no entries, so we should delete the enforcer for that
	// program type
	if !newFiles.HasEntries() {
		if err := prog.enf.Close(); err != nil {
			return err
		}
		delete(la.progs, progType)
		return nil
	}

	var toAddPair, toRemovePair *compiler.AllowDenyPair
	toAddPair = prog.files.DiffPair(newFiles)
	toRemovePair = newFiles.DiffPair(prog.files)

	hasFileChanges := (toAddPair != nil && toAddPair.HasEntries()) || (toRemovePair != nil && toRemovePair.HasEntries())

	if hasFileChanges {
		if toAddPair.HasEntries() {
			if err := prog.enf.AddTargets(toAddPair); err != nil {
				return err
			}
		}
		if toRemovePair.HasEntries() {
			if err := prog.enf.DeleteTargets(toRemovePair); err != nil {
				return err
			}
		}
		defaultDeny := slices.Contains(newFiles.Deny, "*")
		if err := prog.enf.SetDefaultDeny(defaultDeny); err != nil {
			return err
		}
	}

	prog.files = newFiles
	return nil
}

func (l *LsmManager) syncPodAttachment(uid string, la *lsmAttachment) {
	for podUid, pod := range l.pods {
		// there is an implicit assumption here that la.selector contains the new selector from the update.
		// if this is no longer the case, the function will be using the old selector to check if we should
		// still match a given pod or no
		if la.selector.Matches(labels.Set(pod.labels)) {
			_, ok := la.attachedPods[podUid]
			if ok {
				// we are already attached to this pod cgid. nothing to do
				continue
			}
			// we aren't attached
			l.logger.V(2).Info("newly matched pod for runtime policy, adding cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
			for _, prog := range la.progs {
				prog.enf.AddCgids(pod.cgids)
			}

			attach(uid, la, podUid, pod)
		} else {
			// we don't match that pod. did we previously match it ?
			podAttachment, ok := la.attachedPods[podUid]
			if ok {
				// yes we did. remove its cgids from the enforcer before dropping the attachment
				l.logger.V(2).Info("pod no longer matches runtime policy, removing cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
				for _, prog := range la.progs {
					prog.enf.DeleteCgids(pod.cgids)
				}

				detach(uid, la, podUid, podAttachment)
			}
		}
	}
}

func attach(policyUid string, la *lsmAttachment, podUid string, pod *podRepresentation) {
	la.attachedPods[podUid] = pod
	pod.attachedLsms[policyUid] = la
}

func detach(policyUid string, la *lsmAttachment, podUid string, pod *podRepresentation) {
	delete(la.attachedPods, podUid)
	delete(pod.attachedLsms, policyUid)
}
