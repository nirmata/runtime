package srv

import (
	"context"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/egressmgr"
	"github.com/nirmata/kyverno-runtime/pkg/events"
	"github.com/nirmata/kyverno-runtime/pkg/lsmmgr"
	pb "github.com/nirmata/kyverno-runtime/pkg/proto/learning"
)

type learningModeGrpcServer struct {
	pb.UnimplementedLearningServiceServer
	lsmManager    *lsmmgr.LsmManager
	egressManager *egressmgr.EgressManager
}

func NewLeaningModeSrv(lsmm *lsmmgr.LsmManager, em *egressmgr.EgressManager) *learningModeGrpcServer {
	return &learningModeGrpcServer{
		lsmManager:    lsmm,
		egressManager: em,
	}
}

func (s *learningModeGrpcServer) Start(ctx context.Context, req *pb.StartRequest) (*pb.StartResponse, error) {
	handlers := []events.LearningIface{s.egressManager, s.lsmManager}

	var wg sync.WaitGroup
	wg.Add(len(handlers))
	// instruct the bpf program handlers to start learning for the pods that match req.Labels
	for _, h := range handlers {
		go func() { defer wg.Done(); h.Start(req.Uid, req.Labels, req.Duration.AsDuration()) }()
	}
	wg.Wait()
	return &pb.StartResponse{}, nil
}

func (s *learningModeGrpcServer) Stop(ctx context.Context, req *pb.StopRequest) (*pb.StopResponse, error) {
	handlers := []events.LearningIface{s.egressManager, s.lsmManager}

	var wg sync.WaitGroup
	wg.Add(len(handlers))
	for _, h := range handlers {
		go func() { defer wg.Done(); h.Stop(req.Uid) }()
	}
	wg.Wait()
	return &pb.StopResponse{}, nil
}

func (s *learningModeGrpcServer) Read(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	ret := &pb.ReadResponse{}

	for _, requestedBehavior := range req.BehaviorKind {
		switch requestedBehavior {
		case pb.BehaviorKind_BEHAVIOR_NETWORK:
			learnedBehaviors, err := s.egressManager.Read(req.Uid)
			if err != nil {
				return nil, err
			}
			ret.Network = learnedBehaviors
		case pb.BehaviorKind_BEHAVIOR_EXEC:
			learnedBehaviors, err := s.lsmManager.Read(req.Uid)
			if err != nil {
				return nil, err
			}
			ret.Exec = learnedBehaviors
		case pb.BehaviorKind_BEHAVIOR_OPEN:
			learnedBehaviors, err := s.lsmManager.Read(req.Uid)
			if err != nil {
				return nil, err
			}
			ret.Open = learnedBehaviors
		}
	}

	return ret, nil
}
