BINARY   := dns_resolver
IMAGE    := dns_resolver
REGISTRY := registry.home.arpa

.PHONY: all build test fmt vet image publish clean

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

publish: image
	podman tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	podman push $(REGISTRY)/$(IMAGE)

clean:
	rm -f $(BINARY)
