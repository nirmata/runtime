package lsmmgr

import (
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/lsm"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"k8s.io/apimachinery/pkg/labels"
)

// progSpec pairs a bpf lsm attach target with the compiled behavior that drives
// it. Iterated in a fixed order so enforcer construction (and its error paths)
// are deterministic.
type progSpec struct {
	progType string
	files    *compiler.AllowDenyPair
}

func progSpecs(compiledRp *compiler.EvaluationResult) []progSpec {
	return []progSpec{
		{progType: lsm.PROG_TYPE_LSM_OPEN, files: compiledRp.Open},
		// exec behaviors are enforced through bprm_check_security; #34 was the
		// gap of compiling EvaluationResult.Exec and never reaching this.
		{progType: lsm.PROG_TYPE_LSM_EXEC, files: compiledRp.Exec},
	}
}

func (l *LsmManager) rpCreated(compiledRp *compiler.EvaluationResult) error {
	l.logger.V(2).Info("runtime policy created", "uid", compiledRp.UID, "mode", compiledRp.Mode)
	observe := compiler.IsObserveMode(compiledRp.Mode)
	if compiledRp.Mode != compiler.ModeEnforce && !observe {
		l.logger.V(2).Info("runtime policy mode needs no lsm attachment", "uid", compiledRp.UID, "mode", compiledRp.Mode)
		return nil
	}

	progMap := make(map[string]*progState)
	for _, spec := range progSpecs(compiledRp) {
		if !spec.files.HasEntries() {
			continue
		}
		enf, err := l.createForProgType(spec.files, spec.progType, observe)
		if err != nil {
			// don't leak the bpf objects of the enforcers built so far, nothing
			// else references them yet
			l.closeProgs(compiledRp.UID, progMap)
			return err
		}
		progMap[spec.progType] = &progState{files: spec.files, enf: enf}
	}

	if len(progMap) == 0 {
		l.logger.V(2).Info("runtime policy created but has no open or exec entries", "uid", compiledRp.UID)
		return nil
	}

	la := &lsmAttachment{
		progs:        progMap,
		attachedPods: make(map[string]*podRepresentation),
		selector:     compiledRp.Selector,
		observe:      observe,
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

	for progType, prog := range la.progs {
		l.addPodCgids(compiledRp.UID, progType, prog, targetCgids)
	}

	return nil
}

func (l *LsmManager) rpUpdated(compiledRp *compiler.EvaluationResult) error {
	l.logger.V(2).Info("runtime policy updated", "uid", compiledRp.UID, "mode", compiledRp.Mode)
	observe := compiler.IsObserveMode(compiledRp.Mode)
	if compiledRp.Mode != compiler.ModeEnforce && !observe {
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

	if la.observe != observe {
		// the mode crossed the observe/enforce line. the difference is which bpf
		// maps are populated at all, so rebuild instead of trying to converge:
		// an observe enforcer must never inherit deny entries, and an enforce
		// enforcer must not start out with the empty maps of an observer.
		l.logger.V(2).Info("runtime policy mode crossed the observe/enforce line, rebuilding attachment",
			"uid", compiledRp.UID, "mode", compiledRp.Mode)
		l.rpDeleted(compiledRp)
		return l.rpCreated(compiledRp)
	}

	la.selector = compiledRp.Selector
	for _, spec := range progSpecs(compiledRp) {
		if err := l.syncProgType(compiledRp.UID, la, spec.files, spec.progType); err != nil {
			return err
		}
	}

	if len(la.progs) == 0 {
		l.rpDeleted(compiledRp)
		return nil
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

// closeProgs releases a half built prog map that was never published.
func (l *LsmManager) closeProgs(rpUID string, progs map[string]*progState) {
	for progType, prog := range progs {
		if err := prog.enf.Close(); err != nil {
			l.logger.Error(err, "failed to cleanup lsm enforcer on error", "uid", rpUID, "progType", progType)
		}
	}
}

// createForProgType loads, programs and attaches one enforcer.
//
// In observe mode the banned and allowed maps are left EMPTY and default-deny is
// never set, so the loaded program cannot return -EPERM for any path: monitor
// policies observe, they never block. Matching happens in userspace over the
// counts read back by CollectObservations.
func (l *LsmManager) createForProgType(pair *compiler.AllowDenyPair, progType string, observe bool) (lsmEnforcer, error) {
	// create the lsm enforcer
	cleanup := false
	enf, err := l.newEnforcer(&l.logger, progType)
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

	if !observe {
		// add targets
		err = enf.AddTargets(pair)
		if err != nil {
			return nil, err
		}

		// set default deny if the compiled policy had the * in its list of files
		defaultDeny := slices.Contains(pair.Deny, compiler.StarTarget)
		if err := enf.SetDefaultDeny(defaultDeny); err != nil {
			return nil, err
		}
	}

	_, err = enf.Attach()
	if err != nil {
		return nil, err
	}
	cleanup = false
	return enf, nil
}

func (l *LsmManager) syncProgType(rpUID string, la *lsmAttachment, newFiles *compiler.AllowDenyPair, progType string) error {
	prog, ok := la.progs[progType]
	if !ok {
		// we are syncing a program type we didn't have an enforcer loaded for before
		// but there aren't any files. we can just ignore that
		if !newFiles.HasEntries() {
			return nil
		}

		enforcer, err := l.createForProgType(newFiles, progType, la.observe)
		if err != nil {
			return err
		}
		ps := &progState{
			enf:   enforcer,
			files: newFiles,
		}
		for _, pod := range la.attachedPods {
			l.addPodCgids(rpUID, progType, ps, pod.cgids)
		}

		la.progs[progType] = ps
		prog = ps
	}

	// the newfiles specify no entries, so we should delete the enforcer for that
	// program type
	if !newFiles.HasEntries() {
		closeErr := prog.enf.Close()
		// drop the prog state even if the close failed. keeping a closed enforcer
		// around would make every later sync operate on dead bpf maps
		delete(la.progs, progType)
		if closeErr != nil {
			return closeErr
		}
		return nil
	}

	// observe-mode enforcers hold no targets at all: record what the policy asks
	// for (userspace matching reads it) but never program the kernel maps.
	if la.observe {
		prog.files = newFiles
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
		defaultDeny := slices.Contains(newFiles.Deny, compiler.StarTarget)
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
			for progType, prog := range la.progs {
				l.addPodCgids(uid, progType, prog, pod.cgids)
			}

			attach(uid, la, podUid, pod)
		} else {
			// we don't match that pod. did we previously match it ?
			podAttachment, ok := la.attachedPods[podUid]
			if ok {
				// yes we did. remove its cgids from the enforcer before dropping the attachment
				l.logger.V(2).Info("pod no longer matches runtime policy, removing cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
				for progType, prog := range la.progs {
					l.removePodCgids(uid, progType, prog, pod.cgids)
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
