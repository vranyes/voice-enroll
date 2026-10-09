.PHONY: build vet fmt test test-race ko push manifests
# Default for local `make ko`; CI overrides per-push via env (see build.yml).
KO_DOCKER_REPO ?= ghcr.io/vranyes/voice-enroll
export KO_DOCKER_REPO
build:
	go build ./...
vet:
	go vet ./...
fmt:
	gofmt -l . | grep . && exit 1 || exit 0
test:
	go test ./...
test-race:
	go test -race -count=10 ./...
ko:
	ko build ./cmd/voice-enroll --bare
push:
	ko build ./cmd/voice-enroll --bare --tags latest --push=true
manifests:
	kustomize build deploy/k8s > /dev/null
