// Package main contains an example identity provider implementation.
package main

import (
	"flag"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

func main() {
	var logr = logger.DefaultLogger
	var baseURLstr = flag.String("idp", "", "The URL to the IDP")
	flag.Parse()

	var baseURL, err = url.Parse(*baseURLstr)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}

	var idpServer, err = samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Logger:      logr,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	var hashedPassword, _ = bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	err = idpServer.Store.Put("/users/alice", samlidp.User{Name: "alice",
		HashedPassword: hashedPassword,
		Groups:         []string{"Administrators", "Users"},
		Email:          "alice@example.com",
		CommonName:     "Alice Smith",
		Surname:        "Smith",
		GivenName:      "Alice",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	err = idpServer.Store.Put("/users/bob", samlidp.User{
		Name:           "bob",
		HashedPassword: hashedPassword,
		Groups:         []string{"Users"},
		Email:          "bob@example.com",
		CommonName:     "Bob Smith",
		Surname:        "Smith",
		GivenName:      "Bob",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	http.ListenAndServe(":8080", idpServer)
}
