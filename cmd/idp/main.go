// Package main contains an example identity provider implementation.
package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/crewjam/saml/samlidp"
	"golang.org/x/crypto/bcrypt"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
var srv *samlidp.Server

type config struct {
	baseURL    *url.URL
	users      []string
	serviceURL string
	key        crypto.PrivateKey
	cert       *x509.Certificate
}

func registerUsers(srv *samlidp.Server, names []string) error {
	for _, name := range names {
		var err = registerUser(srv, name)
		if err != nil {
			return fmt.Errorf("registering user %q: %w", name, err)
		}
	}

	return nil
}

// registerUser creates a new [samlidp.User], marshals to JSON, and then fakes
// an HTTP request to srv because there's *no public API* for registering
// users. We can manually store users in the datastore, but that seems likely
// to be even more brittle than this.
func registerUser(srv *samlidp.Server, name string) error {
	var pwd, err = bcrypt.GenerateFromPassword([]byte(name), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generating bcrypt password: %w", err)
	}

	var user = samlidp.User{Name: name, HashedPassword: pwd, Email: name + "@uoregon.edu"}
	var data []byte
	data, err = json.Marshal(user)
	if err != nil {
		return fmt.Errorf("marshaling user: %w", err)
	}

	logger.Info("Registering user", "name", name)

	var req *http.Request
	req, err = newTestRequest("PUT", "/users/"+name, data, map[string]string{"id": name})
	if err != nil {
		return fmt.Errorf("creating test request: %w", err)
	}
	var w = newResponseRecorder()
	srv.HandlePutUser(w, req)
	if !w.IsSuccess() {
		return fmt.Errorf("failed http call to PUT user")
	}

	logger.Info("User registration successful", "name", name)
	return nil
}

// registerService fetches the metadata from url and fakes an HTTP call to srv
// because there's *no public API* for registering a service. We can't even
// manually store data in the datastore because of all the magic that samlidp
// does, again with no public API.
func registerService(srv *samlidp.Server, url string) error {
	// Grab the XML metadata
	var resp, err = http.Get(url)
	if err != nil {
		return fmt.Errorf("fetching SAML SP metadata: %w", err)
	}
	var data []byte
	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading data from server metadata URL: %w", err)
	}

	logger.Info("Registering service", "url", url)

	var req *http.Request
	req, err = newTestRequest("PUT", "/services/1", data, map[string]string{"id": "1"})
	if err != nil {
		return fmt.Errorf("creating test request: %w", err)
	}
	var w = newResponseRecorder()
	srv.HandlePutService(w, req)
	if !w.IsSuccess() {
		return fmt.Errorf("failed http call to PUT service")
	}

	logger.Info("Service registration successful", "url", url)
	return nil
}

func initialize() (c *config, err error) {
	c = &config{}

	var val = os.Getenv("IDP_BASE_URL")
	if val == "" {
		return nil, errors.New("IDP_BASE_URL cannot not be blank")
	}
	c.baseURL, err = url.Parse(val)
	if err != nil {
		return nil, fmt.Errorf("IDP_BASE_URL is invalid: %w", err)
	}
	if c.baseURL.Port() == "" {
		return nil, fmt.Errorf("IDP_BASE_URL is invalid: port must explicitly be set")
	}
	logger.Info("IDP base URL set successfully", "IDP_BASE_URL", val)

	val = os.Getenv("IDP_USERS")
	if val != "" {
		c.users = strings.Split(val, ",")
	}

	val = os.Getenv("IDP_SERVICE_URL")
	if val != "" {
		c.serviceURL = val
	}

	c.key, err = getPrivateKey()
	if err != nil {
		return nil, err
	}
	c.cert, err = getCertificate()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func usageExit(code int) {
	fmt.Fprintf(os.Stdout, `
Usage: IDP_BASE_URL=<url to this service> [other env options] %s

Starts a dev-friendly SAML IDP service listening on the URL's port.
Configuration is specified via environment variables:

- IDP_BASE_URL: Required. The URL and port this service will listen on.
- IDP_USERS: Optional. List of comma-separated users to be provisioned.
  Passwords will be set to their username.
- IDP_SERVICE_URL: Optional. URL to a service provider's metadata. If set, the
  service provider is pre-registered for use with this IDP.

`, os.Args[0])
	os.Exit(code)
}

func main() {
	var conf, err = initialize()
	if err != nil {
		logger.Error("Unable to initialize application", "error", err)
		usageExit(1)
	}

	srv, err = samlidp.New(samlidp.Options{
		URL:         *conf.baseURL,
		Key:         conf.key,
		Certificate: conf.cert,
		Logger:      &legacyLog{logger.With("caller", "idp")},
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logger.Error("Unable to create new IDP instance", "error", err)
		usageExit(1)
	}

	if conf.users != nil {
		err = registerUsers(srv, conf.users)
		if err != nil {
			logger.Error("Unable to register users", "error", err, "users", conf.users)
		}
	}

	if conf.serviceURL != "" {
		err = registerService(srv, conf.serviceURL)
		if err != nil {
			logger.Error("Unable to register service", "error", err, "IDP_SERVICE_URL", conf.serviceURL)
		}
	}

	var bind = ":" + conf.baseURL.Port()
	logger.Info("Starting server", "bind address", bind)
	err = http.ListenAndServe(bind, srv)
	if err != nil {
		logger.Error("Unable to start HTTP listener", "error", err)
	}
}
