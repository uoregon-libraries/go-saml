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

## Switching Users

This IdP does not support SAML Single Logout (SLO). To switch between test
users during development, you need to clear the session on both the SP and the
IdP. Sign out of your SP application first, then use one of these strategies to
clear the IdP session:

**Clear browser cookies:** Delete cookies for the IdP's domain (e.g.,
`localhost`). This forces re-authentication on the next SP-initiated login.

**Use the `clear-sessions` command:** Run `make` to build, then clear all
sessions at once:

```bash
./bin/clear-sessions http://localhost:8000
```

**Delete sessions via REST API:** Session IDs may contain characters like `+`,
`/`, and `=` that must be URL-encoded:

```bash
# List active sessions
curl http://localhost:8000/sessions/

# Delete a specific session by ID (URL-encoding special characters)
curl -X DELETE http://localhost:8000/sessions/$(python3 -c "import urllib.parse; print(urllib.parse.quote('<session-id>', safe=''))")
```

**Restart the IdP:** Sessions are stored in memory only, so restarting the
process wipes all sessions.

## Cert

Right now our certificate and private key are hard-coded (again please never
use this in production). To set up a service provider, you need the cert. You
can find it in `cmd/idp/certs.go`, though many SPs can just grab the public key
from the idp's metadata endpoint (`/metadata`)
