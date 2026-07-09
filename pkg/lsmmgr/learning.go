package lsmmgr

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/labels"
)

func (l *LsmManager) Start(uid string, matchLabels map[string]string, dur time.Duration) {
	l.logger.V(2).Info("starting learning mode", "uid", uid, "matchLabels", matchLabels, "duration", dur)
	selector := labels.SelectorFromSet(matchLabels)
	ctx, cancel := context.WithTimeout(context.Background(), dur)

	// this function is called from the grpc server, which may clash with the informers
	l.mu.Lock()

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
				if err := lsmAtt.enf.SetLearningModeForCgids(pod.cgids, true); err != nil {
					l.logger.Error(err, "failed to enable learning mode for pod", "podUid", podUid)
				}
				wp.pods[podUid] = pod
			}
		}
	}
	l.mu.Unlock()

	go func() {
		// when the timeout expires or when someone calls Stop, delete this workload
		// profile from the tracking data structures (pod maps and the wp map) and if
		// this is the last workload profile that specified learning should be active
		// for a pod, set the learning mode flag to false
		<-ctx.Done()
		l.logger.V(2).Info("learning mode window expired", "uid", uid)

		l.mu.Lock()
		defer l.mu.Unlock()

		workloadProfile, ok := l.wps[uid]
		if !ok {
			return
		}
		delete(l.wps, uid)
		for podUid, pa := range workloadProfile.pods {
			delete(pa.learningEnabled, uid)
			if len(pa.learningEnabled) == 0 {
				l.logger.V(2).Info("no more active learning windows for pod, disabling learning mode", "uid", uid, "podUid", podUid)
				for _, la := range pa.attachedLsms {
					if err := la.enf.SetLearningModeForCgids(pa.cgids, false); err != nil {
						l.logger.Error(err, "failed to disable learning mode for pod", "podUid", podUid)
					}
				}
			}
		}
	}()
}

func (l *LsmManager) Stop(uid string) {
	l.logger.V(2).Info("stopping learning mode", "uid", uid)
	l.mu.Lock()
	defer l.mu.Unlock()
	wp, ok := l.wps[uid]
	if !ok {
		return
	}
	wp.cancel()
}

func (l *LsmManager) Read(uid string) (map[string]uint32, error) {
	l.logger.V(2).Info("reading learning mode results", "uid", uid)
	l.mu.Lock()
	defer l.mu.Unlock()
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
