package egressmgr

import (
	"context"
	"fmt"
	"time"

	"github.com/nirmata/kyverno-runtime/pkg/bpf/egressfilter"
	"k8s.io/apimachinery/pkg/labels"
)

func (e *EgressManager) Start(uid string, matchLabels map[string]string, dur time.Duration) {
	e.logger.V(2).Info("starting learning mode", "uid", uid, "matchLabels", matchLabels, "duration", dur)
	selector := labels.SelectorFromSet(matchLabels)
	ctx, cancel := context.WithTimeout(context.Background(), dur)

	wp := &workloadProfile{
		pods:   make(map[string]*podAttachment),
		cancel: cancel,
	}
	e.wps[uid] = wp

	for podUid, p := range e.pods {
		if selector.Matches(labels.Set(p.labels)) {
			// theoretically, there might be a pod with a nil filter. but its intentional
			// to not check for this. because the correct thing is to create a filter on pod
			// creation automatically even if we won't add any IPs. if this is not in place
			// then thats a programming error and we should panic
			p.filter.SetFlagIdx(egressfilter.LEARNING_MODE, true)

			// mark that this pod's behavior is being learned through this uid
			p.learningEnabled[uid] = struct{}{}
			wp.pods[podUid] = p
		}
	}

	go func() {
		// when the timeout expires or when someone calls Stop, delete this workload
		// profile from the tracking data structures (pod maps and the wp map) and if
		// this is the last workload profile that specified learning should be active
		// for a pod, set the learning mode flag to false
		<-ctx.Done()
		e.logger.V(2).Info("learning mode window expired", "uid", uid)
		workloadProfile, ok := e.wps[uid]
		if !ok {
			return
		}
		delete(e.wps, uid)
		for podUid, pa := range workloadProfile.pods {
			delete(pa.learningEnabled, uid)
			if len(pa.learningEnabled) == 0 {
				e.logger.V(2).Info("no more active learning windows for pod, disabling learning mode", "uid", uid, "podUid", podUid)
				pa.filter.SetFlagIdx(egressfilter.LEARNING_MODE, true)
			}
		}
	}()
}

func (e *EgressManager) Stop(uid string) {
	e.logger.V(2).Info("stopping learning mode", "uid", uid)
	wp, ok := e.wps[uid]
	if !ok {
		return
	}
	// the goroutine spawned at Start will handle removal of the workload profile uid from the
	// tracking data structures
	wp.cancel()
}

func (e *EgressManager) Read(uid string) (map[uint32]uint32, error) {
	e.logger.V(2).Info("reading learning mode results", "uid", uid)
	ret := make(map[uint32]uint32)
	wp, ok := e.wps[uid]
	if !ok {
		return nil, fmt.Errorf("got a read request for a workload profile that doesn't exist")
	}
	for _, pod := range wp.pods {
		learnedFromPod, err := pod.filter.ReadLearned()
		if err != nil {
			return nil, err
		}
		for learnedIp, count := range learnedFromPod {
			ret[learnedIp] += uint32(count)
		}
	}

	return ret, nil
}
