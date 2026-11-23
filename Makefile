BINARY   := dns_resolver
IMAGE    := dns_resolver
REGISTRY := registry.home.arpa

.PHONY: all build test fmt vet image publish clean guard-release-versions

all: build

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY)

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

image:
	podman build -t $(IMAGE) .

# What is published is built from releases of my modules, never from a commit under test (a
# pseudo-version): https://wiki.vvvp.se/?page=go-module-versions. GOWORK=off reads the module graph the
# image is built from, and a failing go list fails the guard rather than passing it. A replaced module
# is checked as what replaces it: a directory in the repo has no version, and a replace onto a
# pseudo-version is caught.
guard-release-versions:
	@modules=$$(GOWORK=off go list -m -f '{{with .Replace}}{{.Path}} {{.Version}}{{else}}{{.Path}} {{.Version}}{{end}}' all) && \
	test_versions=$$(printf '%s\n' "$$modules" | grep -E '^github\.com/(Motmedel|altshiftab|vphpersson|intilgroup)/[^ ]* v[^ ]*[0-9]{14}-[0-9a-f]{12}$$' || true) && \
	if [ -n "$$test_versions" ]; then printf '[deploy] Built from test versions of my modules; release them first:\n%s\n' "$$test_versions" >&2; exit 1; fi

publish: guard-release-versions image
	podman tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	podman push $(REGISTRY)/$(IMAGE)

clean:
	rm -f $(BINARY)
