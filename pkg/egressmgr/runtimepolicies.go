package egressmgr

import (
	"github.com/nirmata/runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/runtime/pkg/bpf/protofilter"
	"github.com/nirmata/runtime/pkg/compiler"
)

// trackableMode reports whether the manager has anything to do for a policy in
// this mode: enforce programs the maps, monitor only observes.
func trackableMode(mode string) bool {
	return mode == compiler.ModeEnforce || compiler.IsObserveMode(mode)
}

func (e *EgressManager) rpCreated(compiledRp *compiler.EvaluationResult) {
	e.logger.V(2).Info("runtime policy created", "uid", compiledRp.UID, "mode", compiledRp.Mode)
	if !trackableMode(compiledRp.Mode) {
		e.logger.V(2).Info("ignoring runtime policy with an unsupported mode", "uid", compiledRp.UID, "mode", compiledRp.Mode)
		return
	}
	e.rps[compiledRp.UID] = compiledRp
	e.recordTargetsCondition(compiledRp)

	for podUid, pod := range e.pods {
		if !compiledRp.AppliesTo.Matches(pod.nsLabels, pod.labels) {
			continue
		}
		e.logger.V(2).Info("new runtime policy matches existing pod", "uid", compiledRp.UID, "podUid", podUid)
		e.attachPolicy(podUid, pod, compiledRp)
	}
}

func (e *EgressManager) rpUpdated(compiledRp *compiler.EvaluationResult) {
	e.logger.V(2).Info("runtime policy updated", "uid", compiledRp.UID, "mode", compiledRp.Mode)
	if !trackableMode(compiledRp.Mode) {
		// the policy left every mode we act on: tear its programming down
		e.rpDeleted(compiledRp)
		return
	}
	currentRp, ok := e.rps[compiledRp.UID]
	if !ok {
		e.rpCreated(compiledRp)
		return
	}

	// a policy crossing the enforce/observe line changes what is programmed for
	// every matched pod, so rebuild rather than diff.
	if compiler.IsObserveMode(currentRp.Mode) != compiler.IsObserveMode(compiledRp.Mode) {
		e.logger.V(2).Info("runtime policy changed enforcement class, rebuilding",
			"uid", compiledRp.UID, "from", currentRp.Mode, "to", compiledRp.Mode)
		e.rpDeleted(currentRp)
		e.rpCreated(compiledRp)
		return
	}

	e.recordTargetsCondition(compiledRp)

	if compiler.IsObserveMode(compiledRp.Mode) {
		e.observeRpUpdated(currentRp, compiledRp)
		return
	}

	// store the old ips because we may need to delete them from a pod's attachment
	// when the policy stops matching, whether or not the ips themselves changed
	oldIps := clonePair(currentRp.IPs)
	oldProtos := clonePair(currentRp.Protocols)

	toAddPair := currentRp.IPs.DiffPair(compiledRp.IPs)
	toRemovePair := compiledRp.IPs.DiffPair(currentRp.IPs)
	toAddProtoPair := currentRp.Protocols.DiffPair(compiledRp.Protocols)
	toRemoveProtoPair := compiledRp.Protocols.DiffPair(currentRp.Protocols)

	// the incoming policy update contains a deny "*"
	hasDefaultDeny := denyHasStar(toAddPair)
	// had default deny before, but doesn't anymore
	defaultDenyRemoved := denyHasStar(toRemovePair)
	hasProtoDefaultDeny := denyHasStar(toAddProtoPair)
	protoDefaultDenyRemoved := denyHasStar(toRemoveProtoPair)

	// update the current runtime behavior's information to point to the new compiled behavior data.
	// the shared pointer itself is never replaced: the pods hold it.
	currentRp.IPs = compiledRp.IPs
	currentRp.Protocols = compiledRp.Protocols
	currentRp.AppliesTo = compiledRp.AppliesTo
	currentRp.Name = compiledRp.Name
	currentRp.Mode = compiledRp.Mode

	for podUid, pod := range e.pods {
		rpMatches := compiledRp.AppliesTo.Matches(pod.nsLabels, pod.labels)
		if _, attached := pod.attachedFilters[compiledRp.UID]; attached {
			// there is no diff and rp still matches, do nothing
			hasDiff := toAddPair.HasEntries() || toRemovePair.HasEntries() ||
				toAddProtoPair.HasEntries() || toRemoveProtoPair.HasEntries()
			if !hasDiff && rpMatches {
				continue
			}

			if !rpMatches {
				e.logger.V(2).Info("runtime policy stopped matching pod, detaching", "uid", compiledRp.UID, "podUid", podUid)
				// the ips to remove are the ones this pod actually got programmed
				// with, not the incoming generation's
				e.detachPolicy(podUid, pod, compiledRp.UID, oldIps, oldProtos)
				continue
			}

			// rp matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			e.logger.V(2).Info("applying target diff for updated runtime policy", "uid", compiledRp.UID, "podUid", podUid,
				"toAddAllow", toAddPair.Allow, "toRemoveAllow", toRemovePair.Allow, "toAddDeny", toAddPair.Deny, "toRemoveDeny", toRemovePair.Deny,
				"toAddProtoAllow", toAddProtoPair.Allow, "toRemoveProtoAllow", toRemoveProtoPair.Allow,
				"toAddProtoDeny", toAddProtoPair.Deny, "toRemoveProtoDeny", toRemoveProtoPair.Deny)
			e.addIps(podUid, compiledRp.UID, pod, toAddPair)
			e.deleteIps(podUid, compiledRp.UID, pod, toRemovePair)
			e.addProtos(podUid, compiledRp.UID, pod, toAddProtoPair)
			e.deleteProtos(podUid, compiledRp.UID, pod, toRemoveProtoPair)

			// both operations are idempotent, so repeating them is harmless
			if hasDefaultDeny {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
				pod.defaultDeny[compiledRp.UID] = struct{}{}
			} else if defaultDenyRemoved {
				delete(pod.defaultDeny, compiledRp.UID)
				if len(pod.defaultDeny) == 0 {
					pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
				}
			}
			if hasProtoDefaultDeny {
				pod.protoFilter.SetFlagIdx(protofilter.DEFAULT_DENY, true)
				pod.protoDefaultDeny[compiledRp.UID] = struct{}{}
			} else if protoDefaultDenyRemoved {
				delete(pod.protoDefaultDeny, compiledRp.UID)
				if len(pod.protoDefaultDeny) == 0 {
					pod.protoFilter.SetFlagIdx(protofilter.DEFAULT_DENY, false)
				}
			}
			continue
		}

		// the rp is not attached to that pod. add its ips if it matches
		if rpMatches {
			e.logger.V(2).Info("updated runtime policy newly matches pod", "uid", compiledRp.UID, "podUid", podUid)
			// attach through the shared pointer the manager tracks, never the
			// incoming generation
			e.attachPolicy(podUid, pod, currentRp)
		}
	}
}

// observeRpUpdated handles an update of a monitor policy. Nothing is ever
// programmed for those, so the only work is keeping the attachments in step with
// the target.
func (e *EgressManager) observeRpUpdated(currentRp, compiledRp *compiler.EvaluationResult) {
	currentRp.IPs = compiledRp.IPs
	currentRp.Protocols = compiledRp.Protocols
	currentRp.AppliesTo = compiledRp.AppliesTo
	currentRp.Name = compiledRp.Name
	currentRp.Mode = compiledRp.Mode

	for podUid, pod := range e.pods {
		matches := compiledRp.AppliesTo.Matches(pod.nsLabels, pod.labels)
		_, attached := pod.attachedFilters[compiledRp.UID]
		switch {
		case matches && !attached:
			e.logger.V(2).Info("updated observe-mode policy newly matches pod", "uid", compiledRp.UID, "podUid", podUid)
			e.attachPolicy(podUid, pod, currentRp)
		case !matches && attached:
			e.logger.V(2).Info("observe-mode policy stopped matching pod, detaching", "uid", compiledRp.UID, "podUid", podUid)
			e.detachPolicy(podUid, pod, compiledRp.UID, nil, nil)
		}
	}
}

func (e *EgressManager) rpDeleted(compiledRp *compiler.EvaluationResult) {
	e.logger.V(2).Info("runtime policy deleted", "uid", compiledRp.UID)
	delete(e.rps, compiledRp.UID)
	for podUid, pod := range e.pods {
		att, ok := pod.attachedFilters[compiledRp.UID]
		if !ok {
			continue
		}
		e.logger.V(2).Info("removing deleted runtime policy from pod", "uid", compiledRp.UID, "podUid", podUid)
		e.detachPolicy(podUid, pod, compiledRp.UID, att.IPs, att.Protocols)
	}
}
