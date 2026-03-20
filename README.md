# Go SAML IDP

This project is a simple dev-only drop-in replacement for a SAML identity
provider. It is not a production-usable idp! The cert and private key are
*hard-coded* in the repository for ease of use, and that would be
**disastrous** for a production setup.

Additionally, the IDP returns users' email addresses as a simple hard-coded
`<name>@uoregon.edu`. The users really need to be more configurable, and this
*will* bite you if you aren't paying very close attention.

## Build

To build simply run `make`. You'll need a supported Go compiler.

## Configure

### Environment Variables

The server is primarily configured through environment variables:

```
Usage: IDP_BASE_URL=<url to this service> [other env options] ./bin/idp

Starts a dev-friendly SAML IDP service listening on the URL's port.
Configuration is specified via environment variables:

- IDP_BASE_URL: Required. The URL and port this service will listen on.
- IDP_USERS: Optional. List of comma-separated users to be provisioned.
  Passwords will be set to their username.
- IDP_SERVICE_URL: Optional. URL to a service provider's metadata. If set, the
  service provider is pre-registered for use with this IDP.
- IDP_SP_AUTOLOAD_DIR: Optional. Name of directory from which to load SP
  metadata. All files that match *.xml in this directory will be loaded.
```

### REST calls

If you don't pre-register users or a service provider, you'll have to do that
stuff at runtime using the REST methods provided by the server. e.g.:

```bash
# Make a user
wget --method=PUT --body-data='{"name": "alice", "password": "hunter2"}' http://localhost:8000/users/alice

# Register the metadata XML for an SP. The "1" can be any arbitrary id you want
# (but must be different per SP), and only matters if you need to reference the
# service again (e.g., via a DELETE call)
wget --method=PUT --body-file=/path/to/metadata.xml http://localhost:8000/services/1
```

More information on these can be found by digging through the [`saml` module's
codebase][1] (unfortunately the documentation doesn't cover the various magic
endpoints).

[1]: <https://pkg.go.dev/github.com/uoregon-libraries/crewjam-saml#section-readme>

## Run

An easy way to run this is to copy `vars-example` to `vars`, adjust the values
as needed, `source vars` and then `./bin/idp`.

If you don't pre-register users or a service provider with environment
variables, this is the time to set things up. You must register at least one SP
and at least one user.

## Cert

Right now our certificate and private key are hard-coded (again please never
use this in production). To set up a service provider, you need the cert. You
can find it in `cmd/idp/certs.go`, though many SPs can just grab the public key
from the idp's metadata endpoint (`/metadata`)

## JSON output to browser?

An odd bug we haven't yet nailed down is that after signing in, you get a blob
of JSON in your browser with various IDP bits of metadata. You are supposed to
get redirected to the SP, but it isn't happening properly. However, the auth
cookies and session info are set properly in both the browser and the IDP, so
if you manually return to the SP, and go to the login page again, you should be
logged in to your SP.

This is an open bug we plan to fix when time permits.
