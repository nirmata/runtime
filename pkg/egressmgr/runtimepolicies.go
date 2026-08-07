package egressmgr

import (
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"k8s.io/apimachinery/pkg/labels"
)

// trackableMode reports whether the manager has anything to do for a policy in
// this mode: enforce programs the maps, monitor only observes.
func trackableMode(mode string) bool {
	return mode == compiler.ModeEnforce || compiler.IsObserveMode(mode)
}

// selectorMatches never panics on a nil selector. Delete events carry only a
// uid, so a nil selector reaching a match loop must mean "matches nothing".
func selectorMatches(sel labels.Selector, lbls map[string]string) bool {
	if sel == nil {
		return false
	}
	return sel.Matches(labels.Set(lbls))
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
		if !selectorMatches(compiledRp.Selector, pod.labels) {
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

	toAddPair := currentRp.IPs.DiffPair(compiledRp.IPs)
	toRemovePair := compiledRp.IPs.DiffPair(currentRp.IPs)

	// the incoming policy update contains a deny "*"
	hasDefaultDeny := slices.Contains(toAddPair.Deny, compiler.StarTarget)
	// had default deny before, but doesn't anymore
	defaultDenyRemoved := slices.Contains(toRemovePair.Deny, compiler.StarTarget)

	// update the current runtime behavior's information to point to the new compiled behavior data.
	// the shared pointer itself is never replaced: the pods hold it.
	currentRp.IPs = compiledRp.IPs
	currentRp.Selector = compiledRp.Selector
	currentRp.Name = compiledRp.Name
	currentRp.Mode = compiledRp.Mode

	for podUid, pod := range e.pods {
		rpMatches := selectorMatches(compiledRp.Selector, pod.labels)
		if _, attached := pod.attachedFilters[compiledRp.UID]; attached {
			// there is no diff and rp still matches, do nothing
			if !toAddPair.HasEntries() && !toRemovePair.HasEntries() && rpMatches {
				continue
			}

			if !rpMatches {
				e.logger.V(2).Info("runtime policy stopped matching pod, detaching", "uid", compiledRp.UID, "podUid", podUid)
				// the ips to remove are the ones this pod actually got programmed
				// with, not the incoming generation's
				e.detachPolicy(podUid, pod, compiledRp.UID, oldIps)
				continue
			}

			// rp matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			e.logger.V(2).Info("applying ip diff for updated runtime policy", "uid", compiledRp.UID, "podUid", podUid,
				"toAddAllow", toAddPair.Allow, "toRemoveAllow", toRemovePair.Allow, "toAddDeny", toAddPair.Deny, "toRemoveDeny", toRemovePair.Deny)
			e.addIps(podUid, compiledRp.UID, pod, toAddPair)
			e.deleteIps(podUid, compiledRp.UID, pod, toRemovePair)

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
// the selector.
func (e *EgressManager) observeRpUpdated(currentRp, compiledRp *compiler.EvaluationResult) {
	currentRp.IPs = compiledRp.IPs
	currentRp.Selector = compiledRp.Selector
	currentRp.Name = compiledRp.Name
	currentRp.Mode = compiledRp.Mode

	for podUid, pod := range e.pods {
		matches := selectorMatches(compiledRp.Selector, pod.labels)
		_, attached := pod.attachedFilters[compiledRp.UID]
		switch {
		case matches && !attached:
			e.logger.V(2).Info("updated observe-mode policy newly matches pod", "uid", compiledRp.UID, "podUid", podUid)
			e.attachPolicy(podUid, pod, currentRp)
		case !matches && attached:
			e.logger.V(2).Info("observe-mode policy stopped matching pod, detaching", "uid", compiledRp.UID, "podUid", podUid)
			e.detachPolicy(podUid, pod, compiledRp.UID, nil)
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
		e.detachPolicy(podUid, pod, compiledRp.UID, att.IPs)
	}
}
