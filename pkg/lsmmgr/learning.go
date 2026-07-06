package lsmmgr

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) Start(uid string, matchLabels map[string]string, dur time.Duration) {
	selector := labels.SelectorFromSet(matchLabels)
	ctx, cancel := context.WithTimeout(context.Background(), dur)

	wp := &workloadProfile{
		pods:   make(map[string]*podRepresentation),
		cancel: cancel,
	}
	l.wps[uid] = wp

	for _, lsmAtt := range l.lsmAttachments {
		for podUid, pod := range lsmAtt.attachedPods {
			if selector.Matches(labels.Set(pod.labels)) {
				// all those programs will end up recording the same resuls into their respective
				// maps for a single pod that matches. so during a read only fetch learned behaviors
				// from the first entry in the pod's lsmAttachment
				lsmAtt.enf.SetLearningModeForCgids(pod.cgids, true)
				wp.pods[podUid] = pod
			}
		}
	}
	go func() {
		// when the timeout expires or when someone calls Stop, delete this workload
		// profile from the tracking data structures (pod maps and the wp map) and if
		// this is the last workload profile that specified learning should be active
		// for a pod, set the learning mode flag to false
		<-ctx.Done()
		workloadProfile, ok := l.wps[uid]
		if !ok {
			return
		}
		delete(l.wps, uid)
		for _, pa := range workloadProfile.pods {
			delete(pa.learningEnabled, uid)
			if len(pa.learningEnabled) == 0 {
				for _, la := range pa.attachedLsms {
					la.enf.SetLearningModeForCgids(pa.cgids, false)
				}
			}
		}
	}()
}

func (l *LsmManager) Stop(uid string) {
	wp, ok := l.wps[uid]
	if !ok {
		return
	}
	wp.cancel()
}

func (l *LsmManager) Read(uid string) (map[string]uint32, error) {
	ret := make(map[string]uint32)
	wp, ok := l.wps[uid]
	if !ok {
		return nil, fmt.Errorf("got a read for a non existing workload profile")
	}
	for _, pod := range wp.pods {
		// all attached lsm enforcers's event tracking map will contain the same data.
		// just get the values from the first entry, break the loop to move on to the next pod
		for _, la := range pod.attachedLsms {
			err := la.enf.GetLearningModeForCgids(ret, pod.cgids)
			if err != nil {
				return nil, err
			}

			break
		}
	}

	return ret, nil
}
