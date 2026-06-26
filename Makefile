MODULE := github.com/nirmata/kyverno-runtime

KIND_CLUSTER_NAME ?= kyverno-runtime
IMAGE_REPOSITORY ?= ghcr.io/nirmata/kyverno-runtime
IMAGE_TAG ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE ?= $(IMAGE_REPOSITORY):$(IMAGE_TAG)
HOST_PLATFORM ?= linux/$(shell go env GOARCH)

generate-crds:
	go run sigs.k8s.io/controller-tools/cmd/controller-gen crd paths=./api/v1alpha1/... output:crd:dir=./charts/kyverno-runtime/crds

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
	$(MAKE) kind-install-manifests

# Install all components using a prebuilt image already present in local docker
# (for example, an image pulled from GHCR in CI tag/release validation).
kind-install-prebuilt:
	$(MAKE) kind-load-image
	$(MAKE) kind-install-manifests

# Shared install logic for both local-build and prebuilt-image flows.
kind-install-manifests:
	kubectl apply -f ./charts/kyverno-runtime/crds
	kubectl wait --for=condition=Established --timeout=60s crd/runtimepolicies.runtime.kyverno.io crd/reports.openreports.io crd/clusterreports.openreports.io
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

# Run Chainsaw e2e tests against a kind cluster with kyverno-runtime installed
test-e2e:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/

test-e2e-quickstart:
	chainsaw test --config test/e2e/.chainsaw.yaml --test-dir test/e2e/quickstart/

smoke-quickstart: test-e2e-quickstart

premerge-smoke: build kind-install smoke-quickstart

# Full CI pipeline: build, deploy to kind, and run e2e tests
test-e2e-install: kind-install test-e2e

# Full CI pipeline reusing a prebuilt image tag (no ko build)
test-e2e-install-prebuilt: kind-install-prebuilt test-e2e

.PHONY: generate-crds generate-client generate-listers generate-informers test fmt lint lint-docs run build ko-build ko-push kind kind-load-image kind-install kind-install-prebuilt kind-install-manifests test-e2e test-e2e-quickstart smoke-quickstart premerge-smoke test-e2e-install test-e2e-install-prebuilt
