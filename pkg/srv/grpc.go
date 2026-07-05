package srv

import (
	"context"
	"sync"

	"github.com/nirmata/kyverno-runtime/pkg/events"
	pb "github.com/nirmata/kyverno-runtime/pkg/proto/learning"
)

type learningModeGrpcServer struct {
	pb.UnimplementedLearningServiceServer
	handlers []events.LearningIface
}

func NewLeaningModeSrv(h []events.LearningIface) *learningModeGrpcServer {
	return &learningModeGrpcServer{
		handlers: h,
	}
}

func (s *learningModeGrpcServer) Start(ctx context.Context, req *pb.StartRequest) (*pb.StartResponse, error) {
	var wg sync.WaitGroup
	wg.Add(len(s.handlers))
	// instruct the bpf program handlers to start learning for the pods that match req.Labels
	for _, h := range s.handlers {
		go func() { defer wg.Done(); h.Start(req.Uid, req.Labels, req.Duration.AsDuration()) }()
	}
	wg.Wait()
	return &pb.StartResponse{}, nil
}

func (s *learningModeGrpcServer) Stop(ctx context.Context, req *pb.StopRequest) (*pb.StopResponse, error) {
	var wg sync.WaitGroup
	wg.Add(len(s.handlers))
	for _, h := range s.handlers {
		go func() { defer wg.Done(); h.Stop(req.Uid) }()
	}
	wg.Wait()
	return &pb.StopResponse{}, nil
}

func (s *learningModeGrpcServer) Read(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	// this is the interesting one. what should be the return type ?
	return &pb.ReadResponse{}, nil
}
