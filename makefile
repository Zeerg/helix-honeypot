.PHONY: help build run tidy docker clean

GO ?= go
IMAGE ?= helix-honeypot:local

help:
	@printf '%s\n' \
	  'build  Build the local binary' \
	  'run    Run the Kubernetes honeypot' \
	  'tidy   Reconcile Go module metadata' \
	  'docker Build the container image' \
	  'clean  Remove local build output'

build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/helix-honeypot ./cmd

run:
	$(GO) run ./cmd

tidy:
	$(GO) mod tidy

docker:
	docker build --tag $(IMAGE) .

clean:
	rm -rf bin
