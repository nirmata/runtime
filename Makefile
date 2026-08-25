MODULE := github.com/nirmata/runtime

KIND_CLUSTER_NAME ?= kyverno-runtime
IMAGE_REPOSITORY ?= ghcr.io/nirmata/kyverno-runtime
IMAGE_TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
HOST_PLATFORM ?= linux/$(shell go env GOARCH)

CHART_DIR := charts/kyverno-runtime
CHART_NAME := kyverno-runtime
# helm push appends the chart name, so this resolves to
# ghcr.io/nirmata/charts/kyverno-runtime and keeps the chart out of the image package.
CHART_REGISTRY ?= oci://ghcr.io/nirmata/charts
CHART_PACKAGE_DIR ?= dist
# Chart version must be valid SemVer; a git describe past the exact tag
# (v0.1.4-5-gabcdef) already is one once the leading v is stripped. Falls back
# to Chart.yaml's version when no v<semver> tag is reachable (a shallow clone,
# or a tree with no tags at all), and either can still be overridden on the
# command line to package a release without editing the file.
GIT_DESCRIBE := $(shell git describe --tags --match 'v[0-9]*.[0-9]*.[0-9]*' --always --dirty 2>/dev/null)
CHART_VERSION ?= $(if $(shell echo "$(GIT_DESCRIBE)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+($$|[-+])' && echo yes),$(patsubst v%,%,$(GIT_DESCRIBE)),$(shell awk '/^version:/ {print $$2; exit}' $(CHART_DIR)/Chart.yaml))
# appVersion names the image tag the packaged chart's DaemonSet pulls, so it
# defaults to IMAGE_TAG: the tag `build`/`ko-build` actually produced, not
# Chart.yaml's placeholder.
CHART_APP_VERSION ?= $(IMAGE_TAG)
CHART_PACKAGE := $(CHART_PACKAGE_DIR)/$(CHART_NAME)-$(CHART_VERSION).tgz

# Pinned tool versions. controller-gen stamps its own version into the
# controller-gen.kubebuilder.io/version annotation of every generated CRD, so an
# unpinned `go run` makes that annotation flap with whatever each developer or
# runner happens to resolve. The code generators resolve to the versions pinned
# in go.mod via the tool directive: bump them there and regenerate.
CHAINSAW_VERSION ?= v0.2.15

# ko resolves through `go install`, not go.mod's tool directive: its dependency
# tree would move this module's own.
KO_VERSION ?= v0.19.1
LOCALBIN := $(abspath bin)
KO := $(LOCALBIN)/ko

# PUSH_HOST is where a pod inside the kind cluster reaches the collector
# running on the host. Docker Desktop resolves it from every container it
# runs, kind nodes included; a Linux kind setup that does not resolve it
# overrides this to the docker bridge gateway IP instead.
PUSH_HOST ?= host.docker.internal
PUSHSINK_CERT_DIR := $(LOCALBIN)/pushsink-certs
PUSHSINK_BIN := $(LOCALBIN)/pushsink-testcollector
PUSHSINK_LOG := $(LOCALBIN)/pushsink-testcollector.log
PUSHSINK_PID := $(LOCALBIN)/pushsink-testcollector.pid

generate-crds:
	go tool controller-gen crd paths=./api/v1alpha1/... output:crd:dir=./charts/kyverno-runtime/crds

# verify-crds fails if the committed CRDs do not match what the pinned
# controller-gen produces from api/v1alpha1. Run in CI so a types change that
# forgets `make generate-crds` cannot merge.
verify-crds:
	$(MAKE) generate-crds
	@git diff --exit-code -- ./charts/kyverno-runtime/crds || { \
		echo ""; \
		echo "ERROR: charts/kyverno-runtime/crds is out of date."; \
		echo "Run 'make generate-crds' (controller-gen pinned in go.mod) and commit the result."; \
		exit 1; \
	}

generate-deepcopy:
	go tool controller-gen object:headerFile=hack/boilerplate.go.txt paths=./api/v1alpha1/...

# verify-deepcopy fails if the committed deepcopy funcs do not match what the
# pinned controller-gen produces from api/v1alpha1. Run in CI so a types
# change that forgets `make generate-deepcopy` cannot merge.
verify-deepcopy:
	$(MAKE) generate-deepcopy
	@git diff --exit-code -- ./api/v1alpha1/zz_generated.deepcopy.go || { \
		echo ""; \
		echo "ERROR: api/v1alpha1/zz_generated.deepcopy.go is out of date."; \
		echo "Run 'make generate-deepcopy' (controller-gen pinned in go.mod) and commit the result."; \
		exit 1; \
	}

# BPF object generation runs in a container: bpf2go needs clang and llvm-strip,
# which developer hosts (darwin) do not have with a BPF target. clang compiles
# with -target bpfel/bpfeb, so the image architecture does not affect the emitted
# bytecode -- only the clang version does, which is why it is pinned in the image
# tag. Bump it deliberately and regenerate every object in the same commit.
BPF_BUILDER_IMAGE ?= kyverno-runtime-bpf-builder:clang19
BPF_OBJECTS := 'pkg/bpf/*/*_bpfe*.o' 'pkg/bpf/*/*_bpfe*.go'
BPF_GOMODCACHE := $(shell go env GOMODCACHE)

bpf-builder-image:
	docker build -t $(BPF_BUILDER_IMAGE) hack/bpf-builder

# Regenerate pkg/bpf/**/*_bpfe{l,b}.{go,o} from the _cprog sources. The container
# runs as the invoking user so the regenerated files are never root-owned on the
# host, even when generation fails partway. Docker creates a missing bind-mount
# source as root, which that unprivileged container then cannot write to, so the
# module cache has to exist on the host before the mount.
generate-bpf: bpf-builder-image
	@mkdir -p $(BPF_GOMODCACHE)
	docker run --rm \
		--user $(shell id -u):$(shell id -g) \
		-v $(CURDIR):/src -w /src \
		-v $(BPF_GOMODCACHE):/go/pkg/mod \
		-e GOFLAGS=-buildvcs=false \
		-e HOME=/tmp \
		-e GOCACHE=/tmp/gocache \
		$(BPF_BUILDER_IMAGE) \
		go generate ./pkg/bpf/...

# The committed objects must be exactly what the pinned toolchain produces from
# the committed C. That is what makes an unreviewable binary diff trustworthy:
# nobody reads bytecode, but CI proves the bytecode came from the source next to
# it. Replaces the hand-recompilation that nothing used to guard.
verify-bpf: generate-bpf
	@if ! git diff --exit-code -- $(BPF_OBJECTS); then \
		echo ""; \
		echo "ERROR: committed BPF objects do not match pkg/bpf/*/_cprog sources."; \
		echo "Run 'make generate-bpf' ($(BPF_BUILDER_IMAGE)) and commit the result."; \
		exit 1; \
	fi

generate-client:
	go tool client-gen \
		--clientset-name versioned \
		--input-base "" \
		--input $(MODULE)/api/v1alpha1 \
		--output-dir ./pkg/client/clientset \
		--output-pkg $(MODULE)/pkg/client/clientset \
		--go-header-file hack/boilerplate.go.txt

generate-listers:
	go tool lister-gen \
		--output-dir ./pkg/client/listers \
		--output-pkg $(MODULE)/pkg/client/listers \
		--go-header-file hack/boilerplate.go.txt \
		$(MODULE)/api/v1alpha1

generate-informers:
	go tool informer-gen \
		--output-dir ./pkg/client/informers \
		--output-pkg $(MODULE)/pkg/client/informers \
		--versioned-clientset-package $(MODULE)/pkg/client/clientset/versioned \
		--listers-package $(MODULE)/pkg/client/listers \
		--go-header-file hack/boilerplate.go.txt \
		$(MODULE)/api/v1alpha1

generate-proto:
	protoc \
		--go_out=. --go_opt=module=$(MODULE) \
		--go-grpc_out=. --go-grpc_opt=module=$(MODULE) \
		proto/*.proto

# test is the default local sweep: unit tests only. The chainsaw and e2e suites
# need a cluster and are separate targets on purpose, so `make test` never
# silently depends on kubectl context.
test: test-unit

# test-unit runs the Go unit suites with the race detector. Everything under
# test/e2e skips itself off-Linux / without root (see test/e2e/bpfsmoke_test.go).
test-unit:
	go test -race ./...

# test-examples validates every manifest under examples/ and every fenced yaml
# policy snippet in the docs: strict decode, exactly one behavior kind, an
# explicit mode, and a successful CEL compile. No cluster needed; `test-unit`
# already covers it via ./...
test-examples:
	go test ./test/examples/...

# test-chainsaw runs the CRD schema / admission conformance suite. It needs a
# cluster with charts/kyverno-runtime/crds applied but NOT the daemon, no image
# and no eBPF-capable kernel.
test-chainsaw:
	kubectl apply -f ./charts/kyverno-runtime/crds
	$(MAKE) wait-crds
	chainsaw test --config test/chainsaw/.chainsaw.yaml --test-dir test/chainsaw/

CRDS := runtimepolicies.runtime.nirmata.io reports.openreports.io clusterreports.openreports.io

# Polled rather than waited on: `kubectl wait --for=condition=Established` evaluates
# every version its watch observes, so a revision published before the status
# subresource is populated aborts the whole command with "accessor error: <nil> is of
# the type <nil>, expected []interface{}" instead of waiting for the next one. Reading
# the condition directly cannot observe that state, because a missing field and a
# missing condition are the same empty string here.
wait-crds:
	@for crd in $(CRDS); do \
		i=0; \
		while [ "$$i" -lt 90 ]; do \
			[ "$$(kubectl get crd $$crd -o jsonpath='{.status.conditions[?(@.type=="Established")].status}' 2>/dev/null)" = "True" ] && break; \
			i=$$((i + 1)); \
			sleep 1; \
		done; \
		if [ "$$i" -ge 90 ]; then \
			echo "ERROR: crd/$$crd did not reach Established within 90s."; \
			kubectl get crd $$crd -o jsonpath='{.status.conditions}' 2>&1 || true; \
			exit 1; \
		fi; \
	done

fmt:
	gofmt -l -w .

lint:
	golangci-lint run ./...

lint-docs:
	npx -y markdownlint-cli2 "**/*.md" "#vendor" "#bin"

run:
	go run ./cmd/kyverno-runtime

build: fmt lint
	go build ./cmd/kyverno-runtime

# A version mismatch reinstalls rather than proceeding: ko stamps the image it
# produces, so the pin only holds if the binary matches it. `ko version` prints
# the bare version and nothing else, so compare it exactly: a substring match
# would accept 0.19.11 for a 0.19.1 pin.
#
# setup-go pins GOTOOLCHAIN=local to the version in go.mod, and ko's own go.mod
# asks for a newer toolchain than that. `go install pkg@version` builds against
# ko's go.mod, so the install has to be allowed to fetch the toolchain ko names
# or it fails outright. Scoped to this one command: nothing that compiles this
# module resolves a toolchain it did not before.
install-ko:
	@if [ ! -x '$(KO)' ] || [ "$$('$(KO)' version 2>/dev/null | sed 's/^v//')" != '$(patsubst v%,%,$(KO_VERSION))' ]; then \
		echo 'installing ko $(KO_VERSION) into $(LOCALBIN)'; \
		rm -f '$(KO)'; \
		GOBIN='$(LOCALBIN)' GOTOOLCHAIN=auto go install github.com/google/ko@$(KO_VERSION); \
	fi

ko-build: install-ko
	KO_DOCKER_REPO=$(IMAGE_REPOSITORY) $(KO) build ./cmd/kyverno-runtime --local --bare --tags=$(IMAGE_TAG) --platform=$(HOST_PLATFORM)

ko-push: install-ko
	KO_DOCKER_REPO=$(IMAGE_REPOSITORY) $(KO) build ./cmd/kyverno-runtime --push=true --bare --tags=$(IMAGE_TAG) --platform=linux/amd64,linux/arm64

# Create a kind cluster and install all components
kind:
	kind create cluster --name $(KIND_CLUSTER_NAME) --config test/e2e/kind-config.yaml || true
	$(MAKE) kind-install

# Load the locally built image into a kind cluster
kind-load-image:
	kind load docker-image $(IMAGE) --name $(KIND_CLUSTER_NAME)

# Install all components into the current cluster
kind-install:
	$(MAKE) ko-build
	$(MAKE) kind-load-image
	$(MAKE) kind-install-manifests

# Install all components using a prebuilt image already present in local docker
# (for example, an image pulled from GHCR in CI tag/release validation).
kind-install-prebuilt:
	$(MAKE) kind-load-image
	$(MAKE) kind-install-manifests

# `helm --wait` and `rollout status` both read a fresh daemonset as rolled out
# while .status.desiredNumberScheduled is still 0, so a caller would see a
# cluster with no daemon on it. Poll for a scheduled pod first.
wait-daemon-rollout:
	@i=0; \
	while [ "$$i" -lt 60 ]; do \
		n=$$(kubectl -n kyverno-runtime get daemonset/kyverno-runtime -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null); \
		[ -n "$$n" ] && [ "$$n" -gt 0 ] 2>/dev/null && break; \
		i=$$((i + 1)); \
		sleep 1; \
	done; \
	if [ "$$i" -ge 60 ]; then \
		echo "ERROR: daemonset/kyverno-runtime scheduled onto no node within 60s."; \
		kubectl -n kyverno-runtime get daemonset,nodes || true; \
		exit 1; \
	fi
	kubectl -n kyverno-runtime rollout status daemonset/kyverno-runtime --timeout=180s

# Shared install logic for both local-build and prebuilt-image flows.
kind-install-manifests:
	kubectl apply -f ./charts/kyverno-runtime/crds
	$(MAKE) wait-crds
	helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
		--namespace kyverno-runtime --create-namespace \
		--set image.repository=$(IMAGE_REPOSITORY) \
		--set image.tag=$(IMAGE_TAG) \
		--set image.pullPolicy=IfNotPresent \
		--set defaultPolicies.enabled=true \
		--set defaultPolicies.policies.credentialAccess=true \
		--wait
	@if [ -f ./charts/kyverno-runtime/templates/default-policies.yaml ]; then \
		helm template kyverno-runtime ./charts/kyverno-runtime \
			--namespace kyverno-runtime \
			--set defaultPolicies.enabled=true \
			--set defaultPolicies.policies.credentialAccess=true \
			--show-only templates/default-policies.yaml | kubectl apply -f -; \
	else \
		echo "Skipping explicit default policy apply: templates/default-policies.yaml not present"; \
	fi
	$(MAKE) wait-daemon-rollout
	@if [ -f ./charts/kyverno-runtime/templates/default-policies.yaml ]; then \
		echo "Verifying default policies are installed..."; \
		for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
			if kubectl get runtimepolicy detect-credential-access >/dev/null 2>&1; then \
				echo "✓ Default policies verified"; \
				exit 0; \
			fi; \
			echo "Default policies not visible yet ($$attempt/20); retrying in 3s"; \
			sleep 3; \
		done; \
		echo "ERROR: Policies not found after Helm installation retries!"; \
		kubectl get runtimepolicies || true; \
		exit 1; \
	else \
		echo "Skipping default policy verification: templates/default-policies.yaml not present"; \
	fi

# Generate a throwaway CA, a server certificate for the collector process
# running on the host, and a client certificate for the daemon, following the
# same openssl commands as docs/dev/DEVELOPMENT.md's "Validating the push
# sink" section. The server SAN covers PUSH_HOST plus localhost, since a
# developer watching the collector directly connects over localhost too.
#
# Cached under PUSHSINK_CERT_DIR and reused across reruns with the same
# PUSH_HOST: the daemon's DaemonSet pod template is unchanged by a Secret's
# bytes changing underneath it, so an already-rolled-out daemon keeps the
# in-memory certificate it started with, and regenerating a fresh CA on every
# run would leave it trusting a CA the collector no longer presents.
# Regenerates automatically when PUSH_HOST changes, since the server SAN is
# bound to it.
kind-push-collector-certs:
	@if [ -f $(PUSHSINK_CERT_DIR)/ca.crt ] && [ "$$(cat $(PUSHSINK_CERT_DIR)/push-host 2>/dev/null)" = "$(PUSH_HOST)" ]; then \
		echo "Reusing existing certificates in $(PUSHSINK_CERT_DIR) (PUSH_HOST=$(PUSH_HOST))"; \
	else \
		mkdir -p $(PUSHSINK_CERT_DIR); \
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
			-subj "/CN=pushsink-test-ca" -keyout $(PUSHSINK_CERT_DIR)/ca.key -out $(PUSHSINK_CERT_DIR)/ca.crt; \
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
			-subj "/CN=$(PUSH_HOST)" \
			-addext "subjectAltName=DNS:$(PUSH_HOST),DNS:localhost,IP:127.0.0.1" \
			-keyout $(PUSHSINK_CERT_DIR)/server.key -out $(PUSHSINK_CERT_DIR)/server.csr; \
		openssl x509 -req -in $(PUSHSINK_CERT_DIR)/server.csr -CA $(PUSHSINK_CERT_DIR)/ca.crt -CAkey $(PUSHSINK_CERT_DIR)/ca.key \
			-CAcreateserial -days 3650 -copy_extensions copy -out $(PUSHSINK_CERT_DIR)/server.crt; \
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
			-subj "/CN=kyverno-runtime-daemon" -keyout $(PUSHSINK_CERT_DIR)/client.key -out $(PUSHSINK_CERT_DIR)/client.csr; \
		openssl x509 -req -in $(PUSHSINK_CERT_DIR)/client.csr -CA $(PUSHSINK_CERT_DIR)/ca.crt -CAkey $(PUSHSINK_CERT_DIR)/ca.key \
			-CAcreateserial -days 3650 -out $(PUSHSINK_CERT_DIR)/client.crt; \
		echo "$(PUSH_HOST)" > $(PUSHSINK_CERT_DIR)/push-host; \
	fi

kind-push-collector-build:
	go build -o $(PUSHSINK_BIN) ./hack/pushsink-testcollector

# Create the daemon's client-side TLS secret in-cluster. The dry-run-apply
# idiom keeps rerunning this idempotent. The collector itself runs on the
# host and reads its certificate files directly, so it needs no Secret.
kind-push-collector-secrets: kind-push-collector-certs
	kubectl -n kyverno-runtime create secret generic pushsink-daemon-push-tls \
		--from-file=ca.crt=$(PUSHSINK_CERT_DIR)/ca.crt \
		--from-file=tls.crt=$(PUSHSINK_CERT_DIR)/client.crt \
		--from-file=tls.key=$(PUSHSINK_CERT_DIR)/client.key \
		--dry-run=client -o yaml | kubectl apply -f -

# Stop a collector left running from a previous invocation, if any.
kind-push-collector-stop:
	@if [ -f $(PUSHSINK_PID) ]; then \
		kill $$(cat $(PUSHSINK_PID)) 2>/dev/null || true; \
		rm -f $(PUSHSINK_PID); \
	fi

# Start the collector as a host process, detached from this `make` invocation
# so it keeps running (and keeps accepting findings) after the target exits.
# Always restarts: the certificates just (re)generated above only take effect
# on a fresh process, so a leftover collector from an earlier run would
# otherwise keep serving a stale server certificate.
kind-push-collector-start: kind-push-collector-build kind-push-collector-certs kind-push-collector-stop
	nohup $(PUSHSINK_BIN) --listen 0.0.0.0:9444 \
		--tls-cert $(PUSHSINK_CERT_DIR)/server.crt \
		--tls-key $(PUSHSINK_CERT_DIR)/server.key \
		--tls-client-ca $(PUSHSINK_CERT_DIR)/ca.crt \
		> $(PUSHSINK_LOG) 2>&1 & echo $$! > $(PUSHSINK_PID)
	@sleep 1
	@if ! kill -0 $$(cat $(PUSHSINK_PID)) 2>/dev/null; then \
		echo "ERROR: pushsink-testcollector exited immediately; see $(PUSHSINK_LOG)"; \
		cat $(PUSHSINK_LOG) || true; \
		exit 1; \
	fi
	@echo "pushsink-testcollector listening on :9444 (pid $$(cat $(PUSHSINK_PID)), log $(PUSHSINK_LOG))"

# Point the daemon's push sink at the host collector and wait for the
# rollout that picks up the new flags and TLS secret.
kind-push-collector-configure: kind-push-collector-secrets kind-push-collector-start
	helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
		--namespace kyverno-runtime --reuse-values \
		--set daemon.push.target=$(PUSH_HOST):9444 \
		--set daemon.push.tls.secretName=pushsink-daemon-push-tls \
		--wait
	$(MAKE) wait-daemon-rollout

# Trigger a real finding and poll the collector's log for it. monitor-egress
# only reports on an actual connection attempt, so this makes one after the
# policy is confirmed applied. Chosen over the exec-based shadow-ai examples
# because it needs only cgroup egress BPF, not the kernel's BPF-LSM open/exec
# hooks, keeping this target's dependency surface to what a stock kind
# cluster provides. Fails loudly with diagnostics from both sides on timeout
# instead of exiting 0 on missing evidence.
kind-push-collector-verify: kind-push-collector-configure
	kubectl apply -f examples/monitoring/monitor-egress/target.yaml
	kubectl apply -f examples/monitoring/monitor-egress/client.yaml
	kubectl wait --for=condition=Ready pod/egress-target pod/egress-client --timeout=60s
	kubectl apply -f examples/monitoring/monitor-egress/policy.yaml
	kubectl wait --for=condition=Applied=True runtimepolicy/monitor-egress --timeout=60s
	@TARGET=$$(kubectl get pod egress-target -o jsonpath='{.status.podIP}'); \
	kubectl exec egress-client -- wget -q -T 3 -O /dev/null "http://$${TARGET}:8080/" || true
	@i=0; \
	while [ "$$i" -lt 30 ]; do \
		if grep -qE '^\{' $(PUSHSINK_LOG) 2>/dev/null; then \
			echo "Received a finding on the push collector."; \
			exit 0; \
		fi; \
		i=$$((i + 1)); \
		sleep 2; \
	done; \
	echo "ERROR: no finding observed on the push collector within 60s."; \
	echo "--- collector log ($(PUSHSINK_LOG)) ---"; \
	tail -n 200 $(PUSHSINK_LOG) 2>&1 || true; \
	echo "--- daemon logs ---"; \
	kubectl -n kyverno-runtime logs -l app.kubernetes.io/name=kyverno-runtime --all-containers --tail=100 || true; \
	echo "If PUSH_HOST=$(PUSH_HOST) is not reachable from pods on this setup (for example a Linux host where host.docker.internal is not resolved), rerun with a reachable address, e.g.:"; \
	echo "  PUSH_HOST=<docker-bridge-gateway-ip> make kind-push-collector"; \
	exit 1

# End-to-end validation of the gRPC findings push sink against the in-repo dev
# test collector: runs the collector as a host process, wires the daemon's
# push TLS at it, and confirms a real finding round-trips. `kind` both
# creates a cluster when none exists and installs the daemon onto one that
# already does, so this works either way.
kind-push-collector: kind kind-push-collector-verify
	@echo "Push sink validated end to end. Keep watching with:"
	@echo "  tail -f $(PUSHSINK_LOG)"
	@echo "Stop the collector with:"
	@echo "  make kind-push-collector-stop"

# Run the whole Chainsaw e2e suite against a kind cluster with kyverno-runtime
# installed, LSM tests included. Those need a host booted with lsm=...,bpf and
# fail loudly on one that is not -- which is the point, and is why no CI job
# calls this target: hosted runners do not qualify and run the narrower
# test-e2e-gate / test-e2e-egress / test-e2e-protocol instead. Docker Desktop's
# LinuxKit VM does qualify, so this is the target to run on a developer machine.
test-e2e:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/

# Every suite a hosted runner can satisfy: all of test/e2e except dispatch-only,
# which needs BPF-LSM. The list is globbed rather than written out, so a new
# suite joins this lane by existing.
#
# chainsaw --include-test-regex / --exclude-test-regex cannot express this:
# neither matches the test name, so passing one silently runs the wrong set.
# Passing the accepted directories is the only reliable selector.
E2E_HOSTED_DIRS := $(filter-out test/e2e/dispatch-only/%, \
	$(sort $(dir $(wildcard test/e2e/*/chainsaw-test.yaml test/e2e/*/*/chainsaw-test.yaml))))

# The suites share a daemon and its BPF maps but not a namespace -- chainsaw
# gives each test its own -- so concurrency here also exercises the per-address
# refcounting that a serial lane never contended.
test-e2e-hosted:
	@test -n "$(E2E_HOSTED_DIRS)" || { echo "ERROR: no suites found under test/e2e/; the glob in E2E_HOSTED_DIRS is stale."; exit 1; }
	chainsaw test --config test/e2e/.chainsaw.yaml --parallel 6 \
		$(foreach d,$(E2E_HOSTED_DIRS),--test-dir $(d))

# Install gate only: image builds, chart installs, daemonset Ready, policies
# accepted. Asserts nothing about eBPF -- see test/e2e/install-gate.
test-e2e-gate:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/install-gate/

# Egress enforcement behavior. Needs cgroup v2 + CAP_BPF; no BPF-LSM required.
test-e2e-egress:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-enforce/

# Application-protocol enforcement behavior. Same kernel requirements as
# test-e2e-egress: cgroup v2 + CAP_BPF, no BPF-LSM.
test-e2e-protocol:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/protocol-enforce/

# Cluster Service target resolution and enforcement. Same kernel requirements as
# test-e2e-egress.
test-e2e-svcref:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-svcref/

# Domain-name enforcement: the cgroup DNS snooper feeding the egress filter. Same
# kernel requirements as test-e2e-egress. The suite runs its own resolver, so it
# needs neither cluster DNS nor egress to the internet.
test-e2e-dns:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-dns/

# Overlapping policies and a pod that starts after the policies selecting it.
# Same kernel requirements as test-e2e-egress.
test-e2e-overlap:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-overlap/

# Egress observation under load: k6 in-cluster against an allow-listed Service
# and a denied CIDR, then asserts the daemon survived it, dropped nothing
# silently, and sized its Report by destination rather than by request volume.
# Same kernel requirements as test-e2e-egress. Not a chainsaw suite and
# deliberately not discoverable as one -- a two-minute load run has no business
# in the parallel correctness lane.
test-e2e-egress-load:
	METRICS_PORT=9090 ./test/e2e/egress-load/run.sh

# BPF-LSM open/exec enforcement behavior on its own. REQUIRES a host booted with
# BPF-LSM ('bpf' in /sys/kernel/security/lsm); test-e2e runs it alongside the
# rest of the suite.
test-e2e-lsm:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/dispatch-only/

# Loads every committed BPF object and fails with the verifier log if the kernel
# rejects one. Needs Linux + root; skips elsewhere. A new program joins this lane
# by adding an entry to the table in test/e2e/bpfverify_test.go -- never by
# editing a workflow. Programs the kernel only accepts with BPF-LSM active skip
# unless NIRMATA_RUNTIME_REQUIRE_BPF_LSM=1, which turns the skip into a failure.
test-bpf-verify:
	go test -count=1 -v ./test/e2e/ -run TestBPFVerify

# Map round trips and LSM attach against a live kernel: what the verifier lane
# deliberately does not do. Needs Linux + root; skips elsewhere.
test-bpf-smoke:
	go test -count=1 -v ./test/e2e/ -run 'TestBPFEgress|TestBPFLsm|TestBPFExecTrace'

smoke-quickstart: test-e2e-gate

premerge-smoke: build kind-install smoke-quickstart

# Full CI pipeline: build, deploy to kind, and run e2e tests
test-e2e-install: kind-install test-e2e

# Full CI pipeline reusing a prebuilt image tag (no ko build)
test-e2e-install-prebuilt: kind-install-prebuilt test-e2e

# helm-verify renders the chart the way CI does: lint, then template with both
# the defaults and the non-default toggles, and fail if anything does not parse.
helm-verify:
	helm lint charts/kyverno-runtime
	helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime > /dev/null
	helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime \
		--set rbac.create=false --set serviceAccount.create=false > /dev/null
	helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime \
		--set daemon.metrics.port=19090 \
		| grep -q -- '--metrics-addr=:19090'
	helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime \
		--set daemon.push.target=collector.example:443 \
		--set daemon.push.tls.secretName=push-tls \
		| grep -q -- '--push-tls-ca=/etc/kyverno-runtime/push-tls/ca.crt'
	helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime \
		--set daemon.reports.enabled=false \
		| grep -q -- '--reports-enabled=false'
	helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime \
		--set daemon.events.enabled=true \
		| grep -q -- '--events-enabled=true'
	@if helm template kyverno-runtime charts/kyverno-runtime --namespace kyverno-runtime \
		--set daemon.events.enabled=true --set daemon.reports.enabled=false > /dev/null 2>&1; then \
		echo "ERROR: daemon.events.enabled=true with daemon.reports.enabled=false rendered, want the chart to reject it"; \
		exit 1; \
	fi
	@echo "helm chart renders"

# helm lints and packages the chart into $(CHART_PACKAGE_DIR) for local inspection or a
# manual push. appVersion is the image tag the DaemonSet will pull, so a package whose
# appVersion names an image that was never pushed installs and then fails ImagePull.
helm: helm-verify
	@mkdir -p $(CHART_PACKAGE_DIR)
	helm package $(CHART_DIR) \
		--destination $(CHART_PACKAGE_DIR) \
		--version $(CHART_VERSION) \
		--app-version $(CHART_APP_VERSION)
	@echo "packaged $(CHART_PACKAGE) (appVersion $(CHART_APP_VERSION) -> $(IMAGE_REPOSITORY):$(CHART_APP_VERSION))"

# helm-push publishes the packaged chart as an OCI artifact. Needs a prior
# `helm registry login ghcr.io`; the release workflow does this from the tag instead.
helm-push: helm
	helm push $(CHART_PACKAGE) $(CHART_REGISTRY)

.PHONY: wait-crds generate-crds verify-crds generate-deepcopy verify-deepcopy generate-client generate-listers generate-informers test test-unit test-examples test-chainsaw fmt lint lint-docs helm-verify helm helm-push run build install-ko ko-build ko-push kind kind-load-image kind-install kind-install-prebuilt kind-install-manifests wait-daemon-rollout kind-push-collector-certs kind-push-collector-build kind-push-collector-secrets kind-push-collector-stop kind-push-collector-start kind-push-collector-configure kind-push-collector-verify kind-push-collector test-e2e test-e2e-hosted test-e2e-gate test-e2e-egress test-e2e-protocol test-e2e-svcref test-e2e-dns test-e2e-overlap test-e2e-egress-load test-e2e-lsm test-bpf-verify test-bpf-smoke smoke-quickstart premerge-smoke test-e2e-install test-e2e-install-prebuilt generate-proto
