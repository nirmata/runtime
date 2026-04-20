KIND_CLUSTER_NAME ?= kyverno-runtime
IMAGE_REPOSITORY ?= ghcr.io/nirmata/kyverno-runtime
IMAGE_TAG ?= prototype
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)

test:
	go test ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run ./...

run:
	go run ./cmd/kyverno-runtime

build: fmt lint
	go build ./cmd/kyverno-runtime

ko-build:
	KO_DOCKER_REPO=$(IMAGE_REPOSITORY) ko build ./cmd/kyverno-runtime --push=false --bare --tags=$(IMAGE_TAG)

ko-push:
	KO_DOCKER_REPO=$(IMAGE_REPOSITORY) ko build ./cmd/kyverno-runtime --push=true --bare --tags=$(IMAGE_TAG)

# Create a kind cluster and install all components
kind-create:
	kind create cluster --name $(KIND_CLUSTER_NAME) || true
	$(MAKE) kind-install

# Load the locally built image into a kind cluster
kind-load-image:
	@docker image inspect $(IMAGE) >/dev/null 2>&1 || (echo "Image $(IMAGE) not found locally. Run 'make ko-build' first." && exit 1)
	kind load docker-image $(IMAGE) --name $(KIND_CLUSTER_NAME)

# Install all components into the current cluster
kind-install:
	$(MAKE) ko-build
	$(MAKE) kind-load-image
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
	chainsaw test --test-dir tests/e2e/

# Full CI pipeline: build, deploy to kind, and run e2e tests
test-e2e-install: kind-install test-e2e

.PHONY: test fmt lint run build ko-build ko-push kind-create kind-load-image kind-install test-e2e test-e2e-install
