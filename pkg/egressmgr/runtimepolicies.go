package egressmgr

import (
	"fmt"
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/utils"

	"k8s.io/apimachinery/pkg/labels"
)

func (e *EgressManager) rpCreated(compiledRp *compiler.EvaluationResult) error {
	e.logger.V(2).Info("runtime policy created", "uid", compiledRp.UID)
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
			pod.defaultDeny[string(compiledRp.UID)] = struct{}{}
		}
	}
	return nil
}

func (e *EgressManager) rpUpdated(compiledRp *compiler.EvaluationResult) error {
	e.logger.V(2).Info("runtime policy updated", "uid", compiledRp.UID)
	currentRp, ok := e.rps[compiledRp.UID]
	if !ok {
		return fmt.Errorf("got an update for a non existing runtime policy uid")
	}
	// store the old ips because we may need to delete them from a pod's attachment if the
	// policy no longer matches, regardless of whether the ips themselves changed
	oldIps := &compiler.AllowDenyPair{
		Allow: append([]string{}, currentRp.IPs.Allow...),
		Deny:  append([]string{}, currentRp.IPs.Deny...),
	}
	// whether the policy already enforced a default deny on its attachments before this update
	hadDefaultDeny := slices.Contains(oldIps.Deny, "*")

	toAddAllow := utils.DiffSlice(currentRp.IPs.Allow, compiledRp.IPs.Allow)
	toRemoveAllow := utils.DiffSlice(compiledRp.IPs.Allow, currentRp.IPs.Allow)

	toAddDeny := utils.DiffSlice(currentRp.IPs.Deny, compiledRp.IPs.Deny)
	toRemoveDeny := utils.DiffSlice(compiledRp.IPs.Deny, currentRp.IPs.Deny)

	// has default deny wasn't there, but now is
	hasDefaultDeny := slices.Contains(toAddDeny, "*")
	// had default deny before, but doesn't anymore
	defaultDenyRemoved := slices.Contains(toRemoveDeny, "*")
	// whether the policy's current (post-update) deny list enforces a default deny at all,
	// used for pods newly matching this policy that have no prior attachment state
	currentHasDefaultDeny := slices.Contains(compiledRp.IPs.Deny, "*")

	// update the current runtime behavior's information to point to the new compiled behavior data
	currentRp.IPs = compiledRp.IPs
	currentRp.Selector = compiledRp.Selector

	e.rps[string(compiledRp.UID)] = compiledRp
	for podUid, pod := range e.pods {
		rpMatches := compiledRp.Selector.Matches(labels.Set(pod.labels))
		if _, attached := pod.attachedFilters[string(compiledRp.UID)]; attached {
			// there is no diff and rp still matches, do nothing
			if len(toRemoveAllow) == 0 && len(toAddAllow) == 0 &&
				len(toAddDeny) == 0 && len(toRemoveDeny) == 0 && rpMatches {
				continue
			}

			if !rpMatches {
				e.logger.V(2).Info("runtime policy no longer matches pod, detaching", "uid", compiledRp.UID, "podUid", podUid)
				// this rp doesn't match anymore. delete the old ips from this attachment's map
				pod.filter.DeleteIps(oldIps)
				delete(pod.attachedFilters, string(compiledRp.UID))

				// nothing further to do if the policy didn't previously have a default deny on this pod
				if !hadDefaultDeny {
					continue
				}

				// delete the policy from the default deny map
				delete(pod.defaultDeny, string(compiledRp.UID))
				// the map is now empty, unset default deny
				if len(pod.defaultDeny) == 0 {
					pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
				}
				continue
			}

			// rp matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			e.logger.V(2).Info("applying ip diff for updated runtime policy", "uid", compiledRp.UID, "podUid", podUid,
				"toAddAllow", toAddAllow, "toRemoveAllow", toRemoveAllow, "toAddDeny", toAddDeny, "toRemoveDeny", toRemoveDeny)
			pod.filter.AddIps(&compiler.AllowDenyPair{Allow: toAddAllow, Deny: toAddDeny})
			pod.filter.DeleteIps(&compiler.AllowDenyPair{Allow: toRemoveAllow, Deny: toRemoveDeny})

			// both those operations are idempotent so its fine to do them even if they were previously done
			if hasDefaultDeny {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
				pod.defaultDeny[string(compiledRp.UID)] = struct{}{}
			} else if defaultDenyRemoved {
				// this policy no longer enforces a default deny on this pod
				delete(pod.defaultDeny, string(compiledRp.UID))
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
			pod.attachedFilters[string(compiledRp.UID)] = currentRp // add that runtime policy's pointer to the attachedFilters map of that pod

			if currentHasDefaultDeny {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, true)
				pod.defaultDeny[string(compiledRp.UID)] = struct{}{}
			}
		}
	}
	return nil
}

func (e *EgressManager) rpDeleted(compiledRp *compiler.EvaluationResult) error {
	e.logger.V(2).Info("runtime policy deleted", "uid", compiledRp.UID)
	delete(e.rps, string(compiledRp.UID))
	for podUid, pod := range e.pods {
		if att, ok := pod.attachedFilters[string(compiledRp.UID)]; ok {
			e.logger.V(2).Info("removing deleted runtime policy from pod", "uid", compiledRp.UID, "podUid", podUid)
			pod.filter.DeleteIps(att.IPs)
			delete(pod.attachedFilters, string(compiledRp.UID))

			// attempt to delete that runtime policy's id from the default deny specifiers.
			// if it didn't exist the length of the map won't change and hence won't reach zero.
			// if it was already zero, then no harm in setting the default deny to false since its
			// an idempotent process
			delete(pod.defaultDeny, string(compiledRp.UID))
			if len(pod.defaultDeny) == 0 {
				pod.filter.SetFlagIdx(egressfilter.DEFAULT_DENY, false)
			}
		}
	}
	return nil
}
