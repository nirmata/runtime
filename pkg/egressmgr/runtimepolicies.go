package egressmgr

import (
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"

	"k8s.io/apimachinery/pkg/labels"
)

func (e *EgressManager) rpCreated(compiledRp *compiler.EvaluationResult) {
	e.logger.V(2).Info("runtime policy created", "uid", compiledRp.UID)
	if compiledRp.Mode != "enforce" {
		return
	}
	e.rps[compiledRp.UID] = compiledRp
	for podUid, pod := range e.pods {
		if !compiledRp.Selector.Matches(labels.Set(pod.labels)) {
			continue
		}
		e.logger.V(2).Info("new runtime policy matches existing pod", "uid", compiledRp.UID, "podUid", podUid)
		pod.filter.AddIps(compiledRp.IPs)
		pod.attachedFilters[compiledRp.UID] = compiledRp

		if slices.Contains(compiledRp.IPs.Deny, "*") {
			pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
			pod.defaultDeny[compiledRp.UID] = struct{}{}
		}
	}
}

func (e *EgressManager) rpUpdated(compiledRp *compiler.EvaluationResult) {
	e.logger.V(2).Info("runtime policy updated", "uid", compiledRp.UID)
	if compiledRp.Mode != "enforce" {
		e.rpDeleted(compiledRp)
		return
	}
	currentRp, ok := e.rps[compiledRp.UID]
	if !ok {
		e.rpCreated(compiledRp)
		return
	}
	// store the old ips because we may need to delete them from a pod's attachment if the
	// policy no longer matches, regardless of whether the ips themselves changed
	oldIps := &compiler.AllowDenyPair{
		Allow: append([]string{}, currentRp.IPs.Allow...),
		Deny:  append([]string{}, currentRp.IPs.Deny...),
	}
	// there was a "*" in oldIps
	hadDefaultDeny := slices.Contains(oldIps.Deny, "*")

	toAddPair := currentRp.IPs.DiffPair(compiledRp.IPs)
	toRemovePair := compiledRp.IPs.DiffPair(currentRp.IPs)

	// the incoming policy update contains a deny "*"
	hasDefaultDeny := slices.Contains(toAddPair.Deny, "*")
	// had default deny before, but doesn't anymore
	defaultDenyRemoved := slices.Contains(toRemovePair.Deny, "*")

	// the incoming policy has a default deny, regardless of whether or no
	// the old one did. we need this for newly matched pods in the policy
	// selector change case
	currentHasDefaultDeny := slices.Contains(compiledRp.IPs.Deny, "*")

	// update the current runtime behavior's information to point to the new compiled behavior data
	currentRp.IPs = compiledRp.IPs
	currentRp.Selector = compiledRp.Selector

	e.rps[compiledRp.UID] = compiledRp
	for podUid, pod := range e.pods {
		rpMatches := compiledRp.Selector.Matches(labels.Set(pod.labels))
		if _, attached := pod.attachedFilters[compiledRp.UID]; attached {
			// there is no diff and rp still matches, do nothing
			if !toAddPair.HasEntries() && !toRemovePair.HasEntries() && rpMatches {
				continue
			}

			if !rpMatches {
				e.logger.V(2).Info("runtime policy no longer matches pod, detaching", "uid", compiledRp.UID, "podUid", podUid)
				// this rp doesn't match anymore. delete the old ips from this attachment's map
				pod.filter.DeleteIps(oldIps)
				delete(pod.attachedFilters, compiledRp.UID)

				// nothing further to do if the policy didn't previously have a default deny on this pod
				if !hadDefaultDeny {
					continue
				}

				// delete the policy from the default deny map
				delete(pod.defaultDeny, compiledRp.UID)
				// the map is now empty, unset default deny
				if len(pod.defaultDeny) == 0 {
					pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
				}
				continue
			}

			// rp matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			e.logger.V(2).Info("applying ip diff for updated runtime policy", "uid", compiledRp.UID, "podUid", podUid,
				"toAddAllow", toAddPair.Allow, "toRemoveAllow", toRemovePair.Allow, "toAddDeny", toAddPair.Deny, "toRemoveDeny", toRemovePair.Deny)
			pod.filter.AddIps(toAddPair)
			pod.filter.DeleteIps(toRemovePair)

			// both those operations are idempotent so its fine to do them even if they were previously done
			if hasDefaultDeny {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
				pod.defaultDeny[compiledRp.UID] = struct{}{}
			} else if defaultDenyRemoved {
				// this policy no longer enforces a default deny on this pod
				delete(pod.defaultDeny, compiledRp.UID)
				// no other policy is enforcing default deny on this pod anymore, unset it
				if len(pod.defaultDeny) == 0 {
					pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
				}
			}
			continue
		}

		// this rp wasn't previously attached to that pod. add its ips if it matches
		if rpMatches {
			e.logger.V(2).Info("updated runtime policy newly matches pod", "uid", compiledRp.UID, "podUid", podUid)
			pod.filter.AddIps(compiledRp.IPs)
			pod.attachedFilters[compiledRp.UID] = currentRp // add that runtime policy's pointer to the attachedFilters map of that pod

			if currentHasDefaultDeny {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
				pod.defaultDeny[compiledRp.UID] = struct{}{}
			}
		}
	}
}

func (e *EgressManager) rpDeleted(compiledRp *compiler.EvaluationResult) {
	e.logger.V(2).Info("runtime policy deleted", "uid", compiledRp.UID)
	delete(e.rps, compiledRp.UID)
	for podUid, pod := range e.pods {
		if att, ok := pod.attachedFilters[compiledRp.UID]; ok {
			e.logger.V(2).Info("removing deleted runtime policy from pod", "uid", compiledRp.UID, "podUid", podUid)
			pod.filter.DeleteIps(att.IPs)
			delete(pod.attachedFilters, compiledRp.UID)

			// attempt to delete that runtime policy's id from the default deny specifiers.
			// if it didn't exist the length of the map won't change and hence won't reach zero.
			// if it was already zero, then no harm in setting the default deny to false since its
			// an idempotent process
			delete(pod.defaultDeny, compiledRp.UID)
			if len(pod.defaultDeny) == 0 {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
			}
		}
	}
}
