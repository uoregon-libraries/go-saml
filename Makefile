.PHONY: bin
bin:
	go build -ldflags="-s -w" -o bin/saml-idp saml-idp/cmd/idp

.PHONY: lint
lint:
	go tool revive ./...

.PHONY: clean
clean:
	rm -f bin/*
