package egressmgr

import (
	"fmt"

	"github.com/nirmata/kyverno-runtime/pkg/compiler"
	"github.com/nirmata/kyverno-runtime/pkg/utils"
	"k8s.io/apimachinery/pkg/labels"
)

func (e *egressManager) rbCreated(compiledRb *compiler.EvaluationResult) error {
	e.rbs[compiledRb.UID] = compiledRb
	for _, pod := range e.pods {
		if !compiledRb.Selector.Matches(labels.Set(pod.labels)) {
			continue
		}
		pod.filter.AddIps(compiledRb.IPs)
		pod.attachedFilters[compiledRb.UID] = compiledRb
	}
	return nil
}

func (e *egressManager) rbUpdated(compiledRb *compiler.EvaluationResult) error {
	currentRb, ok := e.rbs[compiledRb.UID]
	if !ok {
		return fmt.Errorf("got an update for a non existing runtime behavior uid")
	}
	oldIps := make([]string, len(currentRb.IPs))

	// store the old ips becuase we may need to delete them from a pod's attachment if the runtime behavior no longer matches
	copy(oldIps, currentRb.IPs)

	toAdd := utils.DiffSlice(currentRb.IPs, compiledRb.IPs)
	toRemove := utils.DiffSlice(compiledRb.IPs, currentRb.IPs)
	// update the current runtime behavior's information to point to the new compiled behavior data
	currentRb.IPs = compiledRb.IPs
	currentRb.Selector = compiledRb.Selector

	e.rbs[string(compiledRb.UID)] = compiledRb
	for _, pod := range e.pods {
		rbMatches := compiledRb.Selector.Matches(labels.Set(pod.labels))
		if ok {
			// there is no diff and rb still matches, do nothing
			if len(toRemove) == 0 && len(toAdd) == 0 && rbMatches {
				continue
			}

			if !rbMatches {
				// this rb doesn't match anymore. delete the old ips from this attachment's map
				pod.filter.DeleteIps(oldIps)
				delete(pod.attachedFilters, string(compiledRb.UID))
				continue
			}

			// rb matches and there is a diff. add the new ips, delete the old
			// and update our tracking data structures
			pod.filter.DeleteIps(toRemove)
			pod.filter.AddIps(toAdd)
			continue
		}

		// this rb wasn't previously attached to that pod. add its ips if it matches
		if rbMatches {
			pod.filter.AddIps(compiledRb.IPs)
			pod.attachedFilters[string(compiledRb.UID)] = currentRb // add that runtime behavior's pointer to the atatchedFilters map of that pod
		}
	}
	return nil
}

func (e *egressManager) rbDeleted(compiledRb *compiler.EvaluationResult) error {
	delete(e.rbs, string(compiledRb.UID))
	for _, pod := range e.pods {
		if att, ok := pod.attachedFilters[string(compiledRb.UID)]; ok {
			pod.filter.DeleteIps(att.IPs)
			delete(pod.attachedFilters, string(compiledRb.UID))
		}
	}
	return nil
}
