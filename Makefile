BINARY   := dns_resolver
IMAGE    := dns_resolver
REGISTRY := registry.vvvp.se
GO_ENV   := GOEXPERIMENT=jsonv2

.PHONY: all build test fmt vet image publish clean

all: build

build:
	$(GO_ENV) CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY)

test:
	$(GO_ENV) go test ./...

fmt:
	gofmt -w .

vet:
	$(GO_ENV) go vet ./...

image:
	podman build -t $(IMAGE) .

publish: image
	podman tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	podman push $(REGISTRY)/$(IMAGE)

clean:
	rm -f $(BINARY)
