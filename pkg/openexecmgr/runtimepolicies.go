package openexecmgr

import (
	"github.com/nirmata/runtime/api/v1alpha1"
	"github.com/nirmata/runtime/pkg/bpf/openexec"
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

func progSpecs(compiledRp *compiler.EvaluationResult, lsm bool) []progSpec {
	progSpecs := []progSpec{
		{progType: openexec.PROG_TYPE_LSM_OPEN, files: compiledRp.Open, condition: v1alpha1.ConditionOpenRulesValid},
		{progType: openexec.PROG_TYPE_LSM_EXEC, files: compiledRp.Exec, condition: v1alpha1.ConditionExecRulesValid},
	}

	if !lsm {
		progSpecs[0].progType = openexec.PROG_TYPE_TRACE_OPEN
		progSpecs[1].progType = openexec.PROG_TYPE_TRACE_EXEC
	}

	return progSpecs
}

func (l *OpenExecManager) rpCreated(compiledRp *compiler.EvaluationResult) error {
	l.logger.V(2).Info("runtime policy created", "uid", compiledRp.UID, "mode", compiledRp.Mode)
	observe := compiler.IsObserveMode(compiledRp.Mode)

	policies := make(map[string]*progState)
	for _, spec := range progSpecs(compiledRp, l.lsm) {
		l.recordPathRulesCondition(compiledRp.UID, spec.condition, spec.files)
		if !spec.files.HasEntries() {
			continue
		}
		enf, err := l.createForProgType(compiledRp.UID, spec.files, spec.progType, observe)
		if err != nil {
			l.reportAttachFailure(compiledRp.UID, spec.progType, observe, err)
			// nothing else references the enforcers built so far
			l.closeProgs(compiledRp.UID, policies)
			return err
		}
		l.clearAttachFailure(compiledRp.UID, spec.progType, observe)
		policies[spec.progType] = &progState{files: spec.files, enf: enf}
	}

	if len(policies) == 0 {
		l.logger.V(2).Info("runtime policy created but has no open or exec entries", "uid", compiledRp.UID)
		return nil
	}

	la := &openExecAttachment{
		policyMaps:   policies,
		attachedPods: make(map[string]*podRepresentation),
		target:       compiledRp.AppliesTo,
		observe:      observe,
	}
	l.openExecAttachments[compiledRp.UID] = la

	targetCgids := []uint64{}
	for podUid, pod := range l.pods {
		if compiledRp.AppliesTo.Matches(pod.nsLabels, pod.labels) {
			attach(compiledRp.UID, la, podUid, pod)
			targetCgids = append(targetCgids, pod.cgids...)
		}
	}

	l.recordCondition(compiledRp.UID, v1alpha1.PodsMatchedCondition(len(la.attachedPods), l.clock()))
	if len(targetCgids) == 0 {
		return nil
	}

	for progType, prog := range la.policyMaps {
		l.addPodCgids(compiledRp.UID, progType, prog, targetCgids, la.observe)
	}

	for _, enforcerProg := range l.programs {
		if err := enforcerProg.EnableObservation(targetCgids); err != nil {
			l.logger.V(4).Error(err, "failed to enable observation for cgids")
		}
	}

	return nil
}

func (l *OpenExecManager) rpUpdated(compiledRp *compiler.EvaluationResult) error {
	l.logger.V(2).Info("runtime policy updated", "uid", compiledRp.UID, "mode", compiledRp.Mode)
	observe := compiler.IsObserveMode(compiledRp.Mode)
	if compiledRp.Mode != compiler.ModeEnforce && !observe {
		l.rpDeleted(compiledRp)
		return nil
	}
	la, ok := l.openExecAttachments[compiledRp.UID]
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
	for _, spec := range progSpecs(compiledRp, l.lsm) {
		l.recordPathRulesCondition(compiledRp.UID, spec.condition, spec.files)
		if err := l.syncProgType(compiledRp.UID, la, spec.files, spec.progType); err != nil {
			return err
		}
	}

	if len(la.policyMaps) == 0 {
		l.rpDeleted(compiledRp)
		return nil
	}

	l.syncPodAttachment(compiledRp.UID, la)
	l.recordCondition(compiledRp.UID, v1alpha1.PodsMatchedCondition(len(la.attachedPods), l.clock()))
	return nil
}

func (l *OpenExecManager) rpDeleted(compiledRp *compiler.EvaluationResult) {
	la, ok := l.openExecAttachments[compiledRp.UID]
	if !ok {
		return
	}
	// Closing the enforcers releases their own cgroup maps, but the sinks are
	// manager-scoped and outlive this attachment: its pods have to leave them
	// here, while the bookkeeping that identifies them still exists.
	if _, mirrored := la.policyMaps[openexec.PROG_TYPE_LSM_EXEC]; mirrored {
		for _, pod := range la.attachedPods {
			l.mirrorCgids(compiledRp.UID, openexec.PROG_TYPE_LSM_EXEC, pod.cgids, false)
		}
	}
	for progKey, prog := range la.policyMaps {
		if err := prog.enf.Close(); err != nil {
			l.logger.Error(err, "failed to close bpf lsm enforcer")
		}
		enforcerProg, ok := l.programs[progKey]
		if !ok {
			continue
		}

		if err := l.stopMonitoringForDeletedRp(enforcerProg, la); err != nil {
			// it's not that big of a deal. log it at a more hidden level
			l.logger.V(4).Error(err, "failed to disable monitoring for cgids")
		}
	}
	delete(l.openExecAttachments, compiledRp.UID)
	for _, pod := range l.pods {
		delete(pod.attachedOpenExecs, compiledRp.UID)
	}
}

// When a policy is deleted, if it was the only policy targeting a cgid, disable monitoring for that cgid
func (l *OpenExecManager) stopMonitoringForDeletedRp(enforcerProg *openexec.Prog, la *openExecAttachment) error {
	cgidsStopMonitoring := []uint64{}
	for _, pod := range la.attachedPods {
		if len(pod.attachedOpenExecs) == 1 {
			cgidsStopMonitoring = append(cgidsStopMonitoring, pod.cgids...)
		}
	}
	if err := enforcerProg.DisableObservation(cgidsStopMonitoring); err != nil {
		return err
	}
	return nil
}

// closeProgs releases a half built prog map that was never published.
func (l *OpenExecManager) closeProgs(rpUID string, progs map[string]*progState) {
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
func (l *OpenExecManager) createForProgType(rpUID string, pair *compiler.AllowDenyPair, progType string, observe bool) (openExecMap, error) {
	// a flag that controls if we should close the enforcer on the kernel side
	// due to an error
	var cleanup bool

	// should be create a map and populate it
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

	cleanup = false
	return enf, nil
}

func (l *OpenExecManager) syncProgType(rpUID string, la *openExecAttachment, newFiles *compiler.AllowDenyPair, progType string) error {
	prog, ok := la.policyMaps[progType]
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

		la.policyMaps[progType] = ps
		prog = ps
	}

	// no entries left to enforce, so the enforcer for this program type goes away
	if !newFiles.HasEntries() {
		closeErr := prog.enf.Close()
		// drop the prog state even if the close failed: keeping a closed enforcer
		// would make every later sync operate on dead bpf maps
		delete(la.policyMaps, progType)
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

func (l *OpenExecManager) syncPodAttachment(uid string, la *openExecAttachment) {
	for podUid, pod := range l.pods {
		// la.target has to already carry the target from the update, otherwise
		// the match below runs against the stale one
		if la.target.Matches(pod.nsLabels, pod.labels) {
			_, ok := la.attachedPods[podUid]
			if ok {
				continue
			}
			l.logger.V(2).Info("newly matched pod for runtime policy, adding cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
			for progType, prog := range la.policyMaps {
				l.addPodCgids(uid, progType, prog, pod.cgids, la.observe)
			}

			attach(uid, la, podUid, pod)
		} else {
			// a pod coming from the manager (all pods) don't match the policy anymore. did it match previously ?
			podAttachment, ok := la.attachedPods[podUid]
			if ok {
				// the cgids leave the enforcer before the attachment is dropped
				l.logger.V(2).Info("pod stopped matching runtime policy, removing cgids", "uid", uid, "podUid", podUid, "cgids", pod.cgids)
				// yeah this should still remove the cgods
				cgidsStopMonitoring := []uint64{}
				for progType, prog := range la.policyMaps {
					l.removePodCgids(uid, progType, prog, pod.cgids)
					// if this is the only policy that tracked a pod, disable monitoring of that pod's cgids
					if len(pod.attachedOpenExecs) == 1 {
						cgidsStopMonitoring = append(cgidsStopMonitoring, pod.cgids...)
					}

					if len(cgidsStopMonitoring) > 0 {
						enforcerProg, ok := l.programs[progType]
						if !ok {
							continue
						}
						if err := enforcerProg.DisableObservation(cgidsStopMonitoring); err != nil {
							l.logger.V(4).Error(err, "failed to disable monitoring")
						}
					}
				}

				detach(uid, la, podUid, podAttachment)
			}
		}
	}
}

// denyHasStar reports whether a deny list carries the default-deny sentinel. It
// reads the answer off openexec.PathKeys so the sentinel is recognized by the same
// schema that decides which values become keys.
func denyHasStar(pair *compiler.AllowDenyPair) bool {
	if pair == nil {
		return false
	}
	_, star, _ := compiler.ParsePathList(pair.Deny)
	return star
}

func attach(policyUid string, la *openExecAttachment, podUid string, pod *podRepresentation) {
	la.attachedPods[podUid] = pod
	pod.attachedOpenExecs[policyUid] = la
}

func detach(policyUid string, la *openExecAttachment, podUid string, pod *podRepresentation) {
	delete(la.attachedPods, podUid)
	delete(pod.attachedOpenExecs, policyUid)
}
