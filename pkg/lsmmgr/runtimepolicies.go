package lsmmgr

import (
	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/bpf/lsm"
	"github.com/nirmata/runtime/pkg/compiler"
)

// progSpec pairs a bpf lsm attach target with the compiled behavior that drives
// it. Iterated in a fixed order so enforcer construction is deterministic.
type progSpec struct {
	progType string
	files    *compiler.AllowDenyPair
	// condition is the status condition type reporting whether this behavior's
	// values can be programmed.
	condition string
}

func progSpecs(compiledRp *compiler.EvaluationResult) []progSpec {
	return []progSpec{
		{progType: lsm.PROG_TYPE_LSM_OPEN, files: compiledRp.Open, condition: v1alpha1.ConditionOpenRulesValid},
		// exec behaviors are enforced through bprm_check_security
		{progType: lsm.PROG_TYPE_LSM_EXEC, files: compiledRp.Exec, condition: v1alpha1.ConditionExecRulesValid},
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
		l.recordPathRulesCondition(compiledRp.UID, spec.condition, spec.files)
		if !spec.files.HasEntries() {
			continue
		}
		enf, err := l.createForProgType(compiledRp.UID, spec.files, spec.progType, observe)
		if err != nil {
			l.reportAttachFailure(compiledRp.UID, spec.progType, observe, err)
			// nothing else references the enforcers built so far
			l.closeProgs(compiledRp.UID, progMap)
			return err
		}
		l.clearAttachFailure(compiledRp.UID, spec.progType, observe)
		progMap[spec.progType] = &progState{files: spec.files, enf: enf}
	}

	if len(progMap) == 0 {
		l.logger.V(2).Info("runtime policy created but has no open or exec entries", "uid", compiledRp.UID)
		return nil
	}

	la := &lsmAttachment{
		progs:        progMap,
		attachedPods: make(map[string]*podRepresentation),
		target:       compiledRp.AppliesTo,
		observe:      observe,
	}
	l.lsmAttachments[compiledRp.UID] = la

	targetCgids := []uint64{}
	for podUid, pod := range l.pods {
		if compiledRp.AppliesTo.Matches(pod.nsLabels, pod.labels) {
			attach(compiledRp.UID, la, podUid, pod)
			targetCgids = append(targetCgids, pod.cgids...)
		}
	}
	l.recordPodsMatchedCondition(compiledRp.UID, len(la.attachedPods))
	if len(targetCgids) == 0 {
		return nil
	}

	for progType, prog := range la.progs {
		l.addPodCgids(compiledRp.UID, progType, prog, targetCgids, la.observe)
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
	la, ok := l.lsmAttachments[compiledRp.UID]
	if !ok {
		// an update that introduces targets for an unattached policy is the first
		// time it needs enforcement, so run it through the creation path
		if !compiledRp.Open.HasEntries() && !compiledRp.Exec.HasEntries() {
			l.logger.V(2).Info("runtime policy update has no open files to enforce and no existing attachment, skipping", "uid", compiledRp.UID)
			return nil
		}
		l.logger.V(2).Info("runtime policy update introduced targets for an unattached policy, creating attachment", "uid", compiledRp.UID)
		return l.rpCreated(compiledRp)
	}

	if la.observe != observe {
		// the mode crossed the observe/enforce line, which changes which bpf maps
		// are populated at all: an observe enforcer holds no deny entries and an
		// enforce one cannot start from an observer's empty maps
		l.logger.V(2).Info("runtime policy mode crossed the observe/enforce line, rebuilding attachment",
			"uid", compiledRp.UID, "mode", compiledRp.Mode)
		l.rpDeleted(compiledRp)
		return l.rpCreated(compiledRp)
	}

	la.target = compiledRp.AppliesTo
	for _, spec := range progSpecs(compiledRp) {
		l.recordPathRulesCondition(compiledRp.UID, spec.condition, spec.files)
		if err := l.syncProgType(compiledRp.UID, la, spec.files, spec.progType); err != nil {
			return err
		}
	}

	if len(la.progs) == 0 {
		l.rpDeleted(compiledRp)
		return nil
	}

	l.syncPodAttachment(compiledRp.UID, la)
	l.recordPodsMatchedCondition(compiledRp.UID, len(la.attachedPods))
	return nil
}

func (l *LsmManager) rpDeleted(compiledRp *compiler.EvaluationResult) {
	delete(l.zeroMatchLogged, compiledRp.UID)
	la, ok := l.lsmAttachments[compiledRp.UID]
	if !ok {
		return
	}
	// Closing the enforcers releases their own cgroup maps, but the sinks are
	// manager-scoped and outlive this attachment: its pods have to leave them
	// here, while the bookkeeping that identifies them still exists.
	if _, mirrored := la.progs[lsm.PROG_TYPE_LSM_EXEC]; mirrored {
		for _, pod := range la.attachedPods {
			l.mirrorCgids(compiledRp.UID, lsm.PROG_TYPE_LSM_EXEC, pod.cgids, false)
		}
	}
	for _, prog := range la.progs {
		if err := prog.enf.Close(); err != nil {
			l.logger.Error(err, "failed to close bpf lsm enforcer")
		}
	}
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

// createForProgType loads, programs and attaches one enforcer. In observe mode
// the banned and allowed maps are left empty and default-deny is unset, so the
// program cannot return -EPERM: matching happens in userspace over the counts
// CollectObservations reads back.
func (l *LsmManager) createForProgType(rpUID string, pair *compiler.AllowDenyPair, progType string, observe bool) (lsmEnforcer, error) {
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
		rejected, err := enf.AddTargets(pair)
		l.logRejected(rpUID, progType, rejected)
		if err != nil {
			return nil, err
		}

		if err := enf.SetDefaultDeny(denyHasStar(pair)); err != nil {
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
		// no enforcer loaded for this program type and no files to enforce
		if !newFiles.HasEntries() {
			return nil
		}

		enforcer, err := l.createForProgType(rpUID, newFiles, progType, la.observe)
		if err != nil {
			l.reportAttachFailure(rpUID, progType, la.observe, err)
			return err
		}
		l.clearAttachFailure(rpUID, progType, la.observe)
		ps := &progState{
			enf:   enforcer,
			files: newFiles,
		}
		for _, pod := range la.attachedPods {
			l.addPodCgids(rpUID, progType, ps, pod.cgids, la.observe)
		}

		la.progs[progType] = ps
		prog = ps
	}

	// no entries left to enforce, so the enforcer for this program type goes away
	if !newFiles.HasEntries() {
		closeErr := prog.enf.Close()
		// drop the prog state even if the close failed: keeping a closed enforcer
		// would make every later sync operate on dead bpf maps
		delete(la.progs, progType)
		// a program type that no longer exists must not keep the shared
		// availability condition False on its account
		l.markGood(rpUID, progType, la.observe)
		if closeErr != nil {
			return closeErr
		}
		return nil
	}

	// observe-mode enforcers hold no targets: record what the policy asks for,
	// which is what userspace matching reads, and program nothing
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
			rejected, err := prog.enf.AddTargets(toAddPair)
			l.logRejected(rpUID, progType, rejected)
			if err != nil {
				return err
			}
		}
		if toRemovePair.HasEntries() {
			rejected, err := prog.enf.DeleteTargets(toRemovePair)
			l.logRejected(rpUID, progType, rejected)
			if err != nil {
				return err
			}
		}
		if err := prog.enf.SetDefaultDeny(denyHasStar(newFiles)); err != nil {
			return err
		}
	}

	prog.files = newFiles
	return nil
}

func (l *LsmManager) syncPodAttachment(uid string, la *lsmAttachment) {
	for podUid, pod := range l.pods {
		// la.target has to already carry the target from the update, otherwise
		// the match below runs against the stale one
		if la.target.Matches(pod.nsLabels, pod.labels) {
			_, ok := la.attachedPods[podUid]
			if ok {
				continue
			}
			l.logger.V(2).Info("newly matched pod for runtime policy, adding cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
			for progType, prog := range la.progs {
				l.addPodCgids(uid, progType, prog, pod.cgids, la.observe)
			}

			attach(uid, la, podUid, pod)
		} else {
			podAttachment, ok := la.attachedPods[podUid]
			if ok {
				// the cgids leave the enforcer before the attachment is dropped
				l.logger.V(2).Info("pod stopped matching runtime policy, removing cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
				for progType, prog := range la.progs {
					l.removePodCgids(uid, progType, prog, pod.cgids)
				}

				detach(uid, la, podUid, podAttachment)
			}
		}
	}
}

// denyHasStar reports whether a deny list carries the default-deny sentinel. It
// reads the answer off lsm.PathKeys so the sentinel is recognized by the same
// schema that decides which values become keys.
func denyHasStar(pair *compiler.AllowDenyPair) bool {
	if pair == nil {
		return false
	}
	_, star, _ := lsm.PathKeys(pair.Deny)
	return star
}

func attach(policyUid string, la *lsmAttachment, podUid string, pod *podRepresentation) {
	la.attachedPods[podUid] = pod
	pod.attachedLsms[policyUid] = la
}

func detach(policyUid string, la *lsmAttachment, podUid string, pod *podRepresentation) {
	delete(la.attachedPods, podUid)
	delete(pod.attachedLsms, policyUid)
}
