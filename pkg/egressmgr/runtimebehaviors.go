package egressmgr

import (
	"fmt"

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
				continue
			}

			// rp matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			pod.filter.AddIps(&compiler.AllowDenyPair{Allow: toAddAllow, Deny: toAddDeny})
			pod.filter.DeleteIps(&compiler.AllowDenyPair{Allow: toRemoveAllow, Deny: toRemoveDeny})
			continue
		}

		// this rp wasn't previously attached to that pod. add its ips if it matches
		if rpMatches {
			pod.filter.AddIps(compiledRp.IPs)
			pod.attachedFilters[string(compiledRp.UID)] = currentRp // add that runtime policy's pointer to the attachedFilters map of that pod
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
		}
	}
	return nil
}
