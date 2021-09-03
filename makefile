.PHONY: help build push tidy run bins windows linux darwin

help:
	    @echo "Makefile commands:"
	    @echo ""
		@echo "run - Go Run main"
		@echo "tidy - Go Mody Tidy"
		@echo "windows - Build windows binary"
		@echo "linux - Build linux binary"
		@echo "darwin - Build mac binary"
		@echo "bins - Make all the bins"
		@echo "clean - Clean the build dir"
	    @echo ""

.DEFAULT_GOAL := build-docker

run:
		@go run main.go

download:
		@go mod download

tidy:
		@go mod tidy

bins: download windows linux darwin

windows: 
		@env GOOS=windows GOARCH=amd64 go build -v -o bin/windows-helix -ldflags="-s -w"  main.go

linux: 
		@env GOOS=linux GOARCH=amd64 go build -v -o bin/linux-helix -ldflags="-s -w"  main.go

darwin: 
		@env GOOS=darwin GOARCH=amd64 go build -v -o bin/darwin-helix -ldflags="-s -w"  main.go

clean:
		@rm -rf bin/
	
