package srv

import "net/http"

type learningModeSrv struct{}

func NewLearningModeSrv() *learningModeSrv {
	return &learningModeSrv{}
}

func (lm *learningModeSrv) ServeHttp(w http.ResponseWriter, r *http.Request) {
	// post -> create a workload profile
	// delete -> stop learning
	// get -> read it
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
	case http.MethodDelete:
	}

}
