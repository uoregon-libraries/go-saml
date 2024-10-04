This package is for using github.com/crewjam/saml with the Go Echo framework (github.com/labstack/echo).

To try it out with the crewjam/saml local test idp:

- modify the .example_env, save as .env, and export
  - SAML_CERT is the path to the certificate
  - SAML_KEY is the path to the key
  - SAML_IDP_METADATA_URL is the url for the identity provider
  - BASE_URL is the url for the service provider
  - HOME_DIR is the directory where main is located
- in example/test_idp, go run main.go
- in example/test_sp, go run main.go
- register the service provider with the identity provider
  - http://localhost:8080/saml/metadata will return the metadata for the service provider, submit this file to the idp using curl: 
`curl -X POST -H 'Content-Type: text/xml' "http://localhost:8000/services/1" -d @metadata`

http://localhost:8080/greets/hello is an endpoint that requires a login;
log in as either alice or bob with pass hunter2
