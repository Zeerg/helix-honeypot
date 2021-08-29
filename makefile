.PHONY: help build push tidy run bins windows linux darwin

help:
	    @echo "Makefile commands:"
	    @echo ""
	    @echo "build - Build the docker file"
	    @echo "push - Push to a repo"
		@echo "up - Bring up docker compose file"
		@echo "windows - Build windows binary"
		@echo "linux - Build linux binary"
		@echo "darwin - Build mac binary"
		@echo "bins - Make all the bins"
	    @echo ""

.DEFAULT_GOAL := build-docker

build-docker:
	    @docker build . --file Dockerfile --tag helixhoneypot/helixhoneypot:latest

push:
	    @docker push helixhoneypot/helixhoneypot:latest

up:
		@docker-compose up -d

run:
		@go run main.go

tidy:
		@go mod tidy

bins: windows linux darwin

windows: 
		@env GOOS=windows GOARCH=amd64 go build -v -o bin/windows-helix -ldflags="-s -w"  main.go

linux: 
		@env GOOS=linux GOARCH=amd64 go build -v -o bin/linux-helix -ldflags="-s -w"  main.go

darwin: 
		@env GOOS=darwin GOARCH=amd64 go build -v -o bin/darwin-helix -ldflags="-s -w"  main.go
	
