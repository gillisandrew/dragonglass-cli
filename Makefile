# Dragonglass CLI Build System
BINARY_NAME=dragonglass
VERSION?=dev
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%d %H:%M:%S UTC')

# Plugin annotation configuration
ANNOTATION_PREFIX?=vnd.obsidian.plugin

# Go build flags
LDFLAGS=-ldflags="-s -w -X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT_HASH)' -X 'main.BuildTime=$(BUILD_TIME)' -X 'github.com/gillisandrew/dragonglass-cli/internal/plugin.AnnotationPrefix=$(ANNOTATION_PREFIX)'"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/dragonglass

# Build for multiple platforms
.PHONY: build-all
build-all: build-darwin build-linux

.PHONY: build-darwin
build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/dragonglass
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/dragonglass

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/dragonglass
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/dragonglass

# Run tests
.PHONY: test
test:
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Install to GOPATH/bin
.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/dragonglass

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Download dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Development build (with debug symbols)
.PHONY: dev
dev:
	go build -ldflags="-X 'github.com/gillisandrew/dragonglass-cli/internal/plugin.AnnotationPrefix=$(ANNOTATION_PREFIX)'" -o bin/$(BINARY_NAME) ./cmd/dragonglass

# Build with custom annotation prefix
.PHONY: build-custom
build-custom:
	@echo "Building $(BINARY_NAME) with annotation prefix: $(ANNOTATION_PREFIX)"
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/dragonglass

# Build for different environments
.PHONY: build-dev
build-dev:
	$(MAKE) build-custom ANNOTATION_PREFIX=dev.obsidian.plugin

.PHONY: build-test
build-test:
	$(MAKE) build-custom ANNOTATION_PREFIX=test.obsidian.plugin

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary"
	@echo "  build-all    - Build for all supported platforms"
	@echo "  build-custom - Build with custom annotation prefix"
	@echo "  build-dev    - Build with dev.obsidian.plugin prefix"
	@echo "  build-test   - Build with test.obsidian.plugin prefix"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install to GOPATH/bin"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  dev          - Development build"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  ANNOTATION_PREFIX - Plugin annotation namespace (default: vnd.obsidian.plugin)"
	@echo "  VERSION          - Build version (default: dev)"
	@echo ""
	@echo "Examples:"
	@echo "  make build ANNOTATION_PREFIX=custom.obsidian.plugin"
	@echo "  make build-dev"
	@echo "  make build-test"