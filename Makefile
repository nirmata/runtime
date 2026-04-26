KIND_CLUSTER_NAME ?= kyverno-runtime
IMAGE_REPOSITORY ?= ghcr.io/nirmata/kyverno-runtime
IMAGE_TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
HOST_PLATFORM ?= linux/$(shell go env GOARCH)

test:
	go test ./...

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
	kind create cluster --name $(KIND_CLUSTER_NAME) || true
	$(MAKE) kind-install

# Load the locally built image into a kind cluster
kind-load-image:
	kind load docker-image $(IMAGE) --name $(KIND_CLUSTER_NAME)

# Install all components into the current cluster
kind-install:
	$(MAKE) ko-build
	$(MAKE) kind-load-image
	kubectl apply -f ./charts/kyverno-runtime/crds
	kubectl apply -f https://raw.githubusercontent.com/openreports/reports-api/refs/heads/main/config/install.yaml
	helm upgrade --install kyverno-runtime ./charts/kyverno-runtime \
		--namespace kyverno-runtime --create-namespace \
		--set image.repository=$(IMAGE_REPOSITORY) \
		--set image.tag=$(IMAGE_TAG) \
		--set image.pullPolicy=IfNotPresent \
		--wait
	kubectl -n kyverno-runtime rollout restart daemonset/kyverno-runtime-kyverno-runtime
	kubectl -n kyverno-runtime rollout status daemonset/kyverno-runtime-kyverno-runtime --timeout=180s

# Run Chainsaw e2e tests against a kind cluster with kyverno-runtime installed
test-e2e:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/

test-e2e-quickstart:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/quickstart/

smoke-quickstart: test-e2e-quickstart

premerge-smoke: build kind-install smoke-quickstart

# Full CI pipeline: build, deploy to kind, and run e2e tests
test-e2e-install: kind-install test-e2e

.PHONY: test fmt lint lint-docs run build ko-build ko-push kind kind-load-image kind-install test-e2e test-e2e-quickstart smoke-quickstart premerge-smoke test-e2e-install
