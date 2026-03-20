VERSION ?= $(shell git describe --tags --always --dirty=-wip)

.PHONY: bin
bin:
	go build -ldflags="-s -w -X main.Version=$(VERSION)" -o bin/idp go-saml/cmd/idp

.PHONY: lint
lint:
	go tool revive ./...

.PHONY: clean
clean:
	rm -f bin/*
