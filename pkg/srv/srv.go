package srv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/nirmata/kyverno-runtime/pkg/proto/learning"
	"github.com/nirmata/kyverno-runtime/pkg/utils"
	"google.golang.org/grpc"
)

type learningModeSrv struct {
	endpointFunc func() []string
	logger       logr.Logger
}

type WorkloadProfileConversionRequest struct {
	Uid           string   `json:"uid,omitempty"`
	BehaviorKinds []uint32 `json:"behaviorKinds,omitempty"`
}

func NewLearningModeSrv(ef func() []string, logger logr.Logger) *learningModeSrv {
	return &learningModeSrv{
		endpointFunc: ef,
		logger:       logger,
	}
}

// this thing should return a policy or create one ?
func (lm *learningModeSrv) ServeHttp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErrResp(lm.logger, w, err)
		return
	}

	var reqBody WorkloadProfileConversionRequest
	if err := json.Unmarshal(body, &reqBody); err != nil {
		writeErrResp(lm.logger, w, err)
		return
	}

	responseAccumulator := &learning.ReadResponse{
		Network: make(map[uint32]uint32),
		Open:    make(map[string]uint32),
		Exec:    make(map[string]uint32),
	}

	requestedBehaviors := []learning.BehaviorKind{}
	for _, b := range reqBody.BehaviorKinds {
		requestedBehaviors = append(requestedBehaviors, learning.BehaviorKind(b))
	}

	for _, ep := range lm.endpointFunc() {
		conn, err := grpc.NewClient(ep)
		if err != nil {
			writeErrResp(lm.logger, w, err)
			return
		}
		c := learning.NewLearningServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()
		readResp, err := c.Read(ctx, &learning.ReadRequest{
			Uid:          reqBody.Uid,
			BehaviorKind: requestedBehaviors,
		})

		// one endpoint failed. thats not a big deal
		if err != nil {
			lm.logger.Error(err, "failed to get learned behavior from endpoint "+ep)
			continue
		}

		utils.MergeMapCount(responseAccumulator.Network, readResp.Network)
		utils.MergeMapCount(responseAccumulator.Open, readResp.Open)
		utils.MergeMapCount(responseAccumulator.Exec, readResp.Exec)
	}

	buf, err := json.Marshal(responseAccumulator)
	if err != nil {
		writeErrResp(lm.logger, w, err)
		return
	}
	writeResponse(lm.logger, w, buf)
}

func writeErrResp(logger logr.Logger, w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, err.Error()) //nolint:errcheck
	logger.Error(err, "an error has occurred")
}

func writeResponse(logger logr.Logger, w http.ResponseWriter, respBytes []byte) {
	w.WriteHeader(200)
	_, err := w.Write(respBytes)
	if err != nil {
		logger.Error(err, "failed to write body")
	}
}
