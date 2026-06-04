.PHONY: build test vet install install-go clean fmt fmt-check lint vulncheck

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/projectdiscovery/depx/internal/cli.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/depx ./cmd/depx

test:
	go test ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

lint:
	golangci-lint run ./...

vulncheck:
	govulncheck ./...

install: build
	install -m 755 bin/depx $(DESTDIR)/usr/local/bin/depx

install-go:
	go install -ldflags "$(LDFLAGS)" ./cmd/depx

clean:
	rm -rf bin/ dist/
