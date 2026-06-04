.PHONY: build test vet install install-go clean fmt fmt-check lint vulncheck ci race race-build golangci-lint

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/projectdiscovery/depx/internal/cli.Version=$(VERSION)

# Official golangci-lint binary (built with Go 1.25+). Homebrew/go install often
# compile with Go 1.24 and fail against go 1.25 modules in this repo.
GOLANGCI_LINT_VERSION ?= v2.5.0
GOLANGCI_LINT := bin/golangci-lint

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

golangci-lint:
	@mkdir -p bin
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b bin $(GOLANGCI_LINT_VERSION)

lint: golangci-lint
	$(GOLANGCI_LINT) run ./...

vulncheck:
	bash scripts/vulncheck.sh

race:
	go test -race ./... -count=1

race-build:
	go build -race ./cmd/depx

# Mirrors .github/workflows/build-test.yml on a single machine.
ci: fmt-check lint vulncheck build test race race-build

install: build
	install -m 755 bin/depx $(DESTDIR)/usr/local/bin/depx

install-go:
	go install -ldflags "$(LDFLAGS)" ./cmd/depx

clean:
	rm -rf bin/ dist/
