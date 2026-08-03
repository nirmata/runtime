MODULE := github.com/nirmata/kyverno-runtime

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
# Default to whatever Chart.yaml carries; override either on the command line to
# package a release without editing the file (the release workflow derives both
# from the git tag).
CHART_VERSION ?= $(shell awk '/^version:/ {print $$2; exit}' $(CHART_DIR)/Chart.yaml)
CHART_APP_VERSION ?= $(shell awk '/^appVersion:/ {gsub(/"/, "", $$2); print $$2; exit}' $(CHART_DIR)/Chart.yaml)
CHART_PACKAGE := $(CHART_PACKAGE_DIR)/$(CHART_NAME)-$(CHART_VERSION).tgz

# Pinned tool versions. controller-gen stamps its own version into the
# controller-gen.kubebuilder.io/version annotation of every generated CRD, so an
# unpinned `go run` makes that annotation flap with whatever each developer or
# runner happens to resolve. Bump this deliberately and regenerate.
CONTROLLER_GEN_VERSION ?= v0.20.0
CHAINSAW_VERSION ?= v0.2.15

generate-crds:
	go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION) crd paths=./api/v1alpha1/... output:crd:dir=./charts/kyverno-runtime/crds

# verify-crds fails if the committed CRDs do not match what the pinned
# controller-gen produces from api/v1alpha1. Run in CI so a types change that
# forgets `make generate-crds` cannot merge.
verify-crds:
	$(MAKE) generate-crds
	@git diff --exit-code -- ./charts/kyverno-runtime/crds || { \
		echo ""; \
		echo "ERROR: charts/kyverno-runtime/crds is out of date."; \
		echo "Run 'make generate-crds' (controller-gen $(CONTROLLER_GEN_VERSION)) and commit the result."; \
		exit 1; \
	}

# BPF object generation runs in a container: bpf2go needs clang and llvm-strip,
# which developer hosts (darwin) do not have with a BPF target. clang compiles
# with -target bpfel/bpfeb, so the image architecture does not affect the emitted
# bytecode -- only the clang version does, which is why it is pinned in the image
# tag. Bump it deliberately and regenerate every object in the same commit.
BPF_BUILDER_IMAGE ?= kyverno-runtime-bpf-builder:clang19
BPF_OBJECTS := 'pkg/bpf/*/*_bpfe*.o' 'pkg/bpf/*/*_bpfe*.go'

bpf-builder-image:
	docker build -t $(BPF_BUILDER_IMAGE) hack/bpf-builder

# Regenerate pkg/bpf/**/*_bpfe{l,b}.{go,o} from the _cprog sources. The container
# runs as the invoking user so the regenerated files are never root-owned on the
# host, even when generation fails partway.
generate-bpf: bpf-builder-image
	docker run --rm \
		--user $(shell id -u):$(shell id -g) \
		-v $(CURDIR):/src -w /src \
		-v $(shell go env GOMODCACHE):/go/pkg/mod \
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
	go run k8s.io/code-generator/cmd/client-gen \
		--clientset-name versioned \
		--input-base "" \
		--input $(MODULE)/api/v1alpha1 \
		--output-dir ./pkg/client/clientset \
		--output-pkg $(MODULE)/pkg/client/clientset \
		--go-header-file hack/boilerplate.go.txt

generate-listers:
	go run k8s.io/code-generator/cmd/lister-gen \
		--output-dir ./pkg/client/listers \
		--output-pkg $(MODULE)/pkg/client/listers \
		--go-header-file hack/boilerplate.go.txt \
		$(MODULE)/api/v1alpha1

generate-informers:
	go run k8s.io/code-generator/cmd/informer-gen \
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

# `kubectl wait --for=condition=X` errors instead of retrying when .status.conditions
# does not exist yet, which the CRD applied last reliably hits: "accessor error: <nil>
# is of the type <nil>, expected []interface{}". Poll for the field first, then wait on
# the condition so a CRD that never establishes still fails the target.
wait-crds:
	@for crd in $(CRDS); do \
		i=0; \
		while [ "$$i" -lt 60 ]; do \
			[ -n "$$(kubectl get crd $$crd -o jsonpath='{.status.conditions}' 2>/dev/null)" ] && break; \
			i=$$((i + 1)); \
			sleep 1; \
		done; \
		if [ "$$i" -ge 60 ]; then \
			echo "ERROR: crd/$$crd published no .status.conditions within 60s; it may not exist."; \
			exit 1; \
		fi; \
		kubectl wait --for=condition=Established --timeout=60s crd/$$crd || exit 1; \
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

ko-build:
	KO_DOCKER_REPO=$(IMAGE_REPOSITORY) ko build ./cmd/kyverno-runtime --local --bare --tags=$(IMAGE_TAG) --platform=$(HOST_PLATFORM)

ko-push:
	KO_DOCKER_REPO=$(IMAGE_REPOSITORY) ko build ./cmd/kyverno-runtime --push=true --bare --tags=$(IMAGE_TAG) --platform=linux/amd64,linux/arm64

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
	kubectl -n kyverno-runtime rollout restart daemonset/kyverno-runtime-kyverno-runtime
	kubectl -n kyverno-runtime rollout status daemonset/kyverno-runtime-kyverno-runtime --timeout=180s
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

# Run the Chainsaw e2e suite against a kind cluster with kyverno-runtime
# installed. test/e2e/dispatch-only is excluded: it needs a kernel booted with
# lsm=...,bpf, which hosted CI runners do not have (issue #60).
test-e2e:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/ --exclude-test-regex '^lsm-'

# Install gate only: image builds, chart installs, daemonset Ready, policies
# accepted. Asserts nothing about eBPF -- see test/e2e/install-gate.
test-e2e-gate:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/install-gate/

# Egress enforcement behavior. Needs cgroup v2 + CAP_BPF; no BPF-LSM required.
test-e2e-egress:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/egress-enforce/

# BPF-LSM open/exec enforcement behavior. REQUIRES a host booted with BPF-LSM
# ('bpf' in /sys/kernel/security/lsm). Not part of test-e2e; see issue #60.
test-e2e-lsm:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/dispatch-only/

# BPF program load / verifier smoke test. Needs Linux + root; skips elsewhere.
test-bpf-smoke:
	go test -count=1 -v ./test/e2e/ -run TestBPF

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

.PHONY: wait-crds generate-crds verify-crds generate-client generate-listers generate-informers test test-unit test-examples test-chainsaw fmt lint lint-docs helm-verify helm helm-push run build ko-build ko-push kind kind-load-image kind-install kind-install-prebuilt kind-install-manifests test-e2e test-e2e-gate test-e2e-egress test-e2e-lsm test-bpf-smoke smoke-quickstart premerge-smoke test-e2e-install test-e2e-install-prebuilt generate-proto
