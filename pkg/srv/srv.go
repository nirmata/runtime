package srv

import "net/http"

type learningModeSrv struct{}

func NewLearningModeSrv() *learningModeSrv {
	return &learningModeSrv{}
}

func (lm *learningModeSrv) ServeHttp(w http.ResponseWriter, r *http.Request) {
	// a single method http server that will go on the controller and signifies a request by the client
	// to convert a workload profile to a policy
	// this server is what will call the grpc client and will contain the learned behavior to policy
	// conversion logic
	// the request should contain the uid of the workload profile. and then we should call read
	// on the client grpc. do some accumulation and send it back
}
