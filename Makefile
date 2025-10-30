.PHONY: bin
bin:
	go build -ldflags="-s -w" -o bin/saml-idp saml-idp/cmd/idp

.PHONY: clean
clean:
	rm -f bin/*
