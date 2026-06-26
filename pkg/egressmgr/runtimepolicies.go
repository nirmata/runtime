package egressmgr

import (
	"fmt"
	"slices"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/utils"
	"k8s.io/apimachinery/pkg/labels"
)

func (e *egressManager) rpCreated(compiledRp *compiler.EvaluationResult) error {
	e.rps[compiledRp.UID] = compiledRp
	for _, pod := range e.pods {
		if !compiledRp.Selector.Matches(labels.Set(pod.labels)) {
			continue
		}
		pod.filter.AddIps(compiledRp.IPs)
		pod.attachedFilters[compiledRp.UID] = compiledRp

		if slices.Contains(compiledRp.IPs.Deny, "*") {
			pod.filter.SetDefaultDeny(true)
			pod.defaultDeny[string(compiledRp.UID)] = struct{}{}
		}
	}
	return nil
}

func (e *egressManager) rpUpdated(compiledRp *compiler.EvaluationResult) error {
	currentRp, ok := e.rps[compiledRp.UID]
	if !ok {
		return fmt.Errorf("got an update for a non existing runtime policy uid")
	}
	oldIps := &compiler.AllowDenyPair{}

	// store the old ips becuase we may need to delete them from a pod's attachment if the runtime behavior no longer matches
	copy(oldIps.Deny, currentRp.IPs.Deny)
	copy(oldIps.Allow, currentRp.IPs.Allow)

	toAddAllow := utils.DiffSlice(currentRp.IPs.Allow, compiledRp.IPs.Allow)
	toRemoveAllow := utils.DiffSlice(compiledRp.IPs.Allow, currentRp.IPs.Allow)

	toAddDeny := utils.DiffSlice(currentRp.IPs.Deny, compiledRp.IPs.Deny)
	toRemoveDeny := utils.DiffSlice(compiledRp.IPs.Deny, currentRp.IPs.Deny)

	// has default deny wasn't there, but now is
	hasDefaultDeny := slices.Contains(toAddDeny, "*")

	// update the current runtime behavior's information to point to the new compiled behavior data
	currentRp.IPs = compiledRp.IPs
	currentRp.Selector = compiledRp.Selector

	e.rps[string(compiledRp.UID)] = compiledRp
	for _, pod := range e.pods {
		rpMatches := compiledRp.Selector.Matches(labels.Set(pod.labels))
		if ok {
			// there is no diff and rp still matches, do nothing
			if len(toRemoveAllow) == 0 && len(toAddAllow) == 0 &&
				len(toAddDeny) == 0 && len(toRemoveDeny) == 0 && rpMatches {
				continue
			}

			if !rpMatches {
				// this rp doesn't match anymore. delete the old ips from this attachment's map
				pod.filter.DeleteIps(oldIps)
				delete(pod.attachedFilters, string(compiledRp.UID))

				// nothing further to do if the policy didn't have a default deny
				if !hasDefaultDeny {
					continue
				}

				// delete the policy from the default deny map
				delete(pod.defaultDeny, string(compiledRp.UID))
				// the map is now empty, unset default deny
				if len(pod.defaultDeny) == 0 {
					pod.filter.SetDefaultDeny(false)
				}
			}

			// rp matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			pod.filter.AddIps(&compiler.AllowDenyPair{Allow: toAddAllow, Deny: toAddDeny})
			pod.filter.DeleteIps(&compiler.AllowDenyPair{Allow: toRemoveAllow, Deny: toRemoveDeny})

			// both those operations are idempotent so its fine to do them even if they were previously done
			if hasDefaultDeny {
				pod.filter.SetDefaultDeny(true)
				pod.defaultDeny[string(compiledRp.UID)] = struct{}{}
			}
			continue
		}

		// this rp wasn't previously attached to that pod. add its ips if it matches
		if rpMatches {
			pod.filter.AddIps(compiledRp.IPs)
			pod.attachedFilters[string(compiledRp.UID)] = currentRp // add that runtime policy's pointer to the attachedFilters map of that pod

			if hasDefaultDeny {
				pod.filter.SetDefaultDeny(true)
				pod.defaultDeny[string(compiledRp.UID)] = struct{}{}
			}
		}
	}
	return nil
}

func (e *egressManager) rpDeleted(compiledRp *compiler.EvaluationResult) error {
	delete(e.rps, string(compiledRp.UID))
	for _, pod := range e.pods {
		if att, ok := pod.attachedFilters[string(compiledRp.UID)]; ok {
			pod.filter.DeleteIps(att.IPs)
			delete(pod.attachedFilters, string(compiledRp.UID))

			// attempt to delete that runtime policy's id from the default deny specifiers.
			// if it didn't exist the length of the map won't change and hence won't reach zero.
			// if it was already zero, then no harm in setting the default deny to false since its
			// an idempotent process
			delete(pod.defaultDeny, string(compiledRp.UID))
			if len(pod.defaultDeny) == 0 {
				pod.filter.SetDefaultDeny(false)
			}
		}
	}
	return nil
}
