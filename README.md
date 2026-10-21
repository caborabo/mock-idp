# mock-idp

**Okta, Entra ID, Google Workspace and six more identity providers, simulated on your laptop.** Test SAML, OIDC and SCIM without begging anyone for a test tenant. Then break them on purpose.

```bash
docker run -p 7070:7070 ghcr.io/ssojet/mock-idp
```

Open http://localhost:7070.

Built by [SSOJet](https://ssojet.com/?utm_source=github&utm_medium=mock-idp). When your tests pass, SSOJet runs enterprise SSO and SCIM for real.

## What you get

- **9 providers, with their quirks.** Okta, Microsoft Entra ID, Google Workspace, OneLogin, PingOne, JumpCloud, AD FS, Auth0, Keycloak, plus a plain generic one. Each has its own id formats, issuer format, claim shapes, SAML attribute names and SCIM client dialect. Entra's pairwise `sub`, missing `email` and `#EXT#` guests. Okta's PUT-only SCIM updates. Google's empty SAML attributes.
- **SAML 2.0 IdP.** Metadata, SP- and IdP-initiated SSO (Redirect and POST bindings), SLO, signed response and/or assertion.
- **OIDC provider.** Discovery, JWKS, authorization code + PKCE, implicit, refresh tokens, client credentials, password grant, userinfo, logout.
- **SCIM client.** Provisions users and groups into *your* app as Okta or Entra would. Auto-push on change, full sync, and a conformance suite.
- **38 simulations.** Expired assertions, clock skew, wrong audience, tampered signatures, unknown signing key, SHA-1, signature wrapping (XSW), comment injection in NameID, alg=none, wrong nonce/state/at_hash, missing email, MFA, consent, lockout, outages, latency. One click, or one API call. `once` clears them after the next sign-in.
- **Built-in test SP and RP.** Press *Test login* and a careful app signs in through the real flow and shows every check it ran. No app needed to see a fault land.
- **Live logs.** Every request and response, with SAML and JWTs decoded and notes on what the IdP decided and why.
- **API and MCP.** Everything the dashboard does is a JSON call, and every call is an MCP tool, so an AI agent can set up tenants, inject faults and read the logs.

## Connect an AI agent

```bash
claude mcp add --transport http mock-idp http://localhost:7070/mcp
```

Plain-text docs for LLMs: http://localhost:7070/llms.txt

## Use it in tests

Skip the login page and break the next sign-in only:

```bash
curl -X PATCH localhost:7070/api/tenants/okta/simulations \
  -H 'content-type: application/json' \
  -d '{"autoLogin": "alice@acme.example", "samlExpired": true, "once": true}'
```

Get tokens or a signed SAMLResponse without a browser:

```bash
curl -X POST localhost:7070/api/tenants/entra/apps/test-oidc/tokens -d '{"user":"alice@contoso.example"}'
curl -X POST localhost:7070/api/tenants/okta/apps/test-saml/saml-response -d '{"user":"alice@acme.example"}'
```

Run the SCIM conformance suite against your app, as Entra:

```bash
curl -X POST localhost:7070/api/tenants/entra/scim-targets -d '{"name":"app","baseUrl":"http://host.docker.internal:3000/scim/v2","token":"secret"}'
curl -X POST localhost:7070/api/tenants/entra/scim-targets/app/conformance -d '{"flavor":"entra"}'
```

## Configuration

| Env | Flag | Default | |
|---|---|---|---|
| `MOCKIDP_ADDR` | `-addr` | `:7070` | listen address |
| `MOCKIDP_BASE_URL` | `-base-url` | `http://localhost:<port>` | URL browsers use; it goes into issuers and redirects |
| `MOCKIDP_DATA` | `-data` | `mockidp-data.json` | state file; empty keeps state in memory |
| `MOCKIDP_API_TOKEN` | | | require `Authorization: Bearer …` on the API and MCP |
| `MOCKIDP_ALLOWED_HOSTS` | | | extra dotted host names allowed to reach the API, e.g. `mockidp.dev.internal` |

The API and MCP refuse requests from other web pages and from unknown dotted host names, so a site you visit cannot drive your local mock-idp (cross-site requests, DNS rebinding). `localhost`, IP addresses, single-label names like a compose service (`mock-idp`) and `host.docker.internal` always work. The IdP endpoints under `/t/` are open to any host.

Seeded apps store absolute URLs. After changing `MOCKIDP_BASE_URL`, run `POST /api/reset`.

## Develop

```bash
go run .
go test ./...
```

One Go binary, two dependencies (`beevik/etree`, `russellhaering/goxmldsig`), and a no-build dashboard in `web/`.

## Tested against real libraries

`interop/run.sh` starts a fresh mock-idp and runs real client libraries against all 9 providers, with every fault:

| Library | What it covers |
|---|---|
| `@node-saml/node-saml` 5.1 (passport-saml's engine) | SP-initiated SAML, attributes, 15 faults |
| `crewjam/saml` 0.5 | SP-initiated SAML, 17 faults |
| `openid-client` 6.8 | code + PKCE, public clients, userinfo, refresh rotation, the real login page, SSO session, MFA, 15 faults |
| `coreos/go-oidc` 3.21 + `x/oauth2` | code + PKCE, userinfo, refresh, 15 faults |
| `@modelcontextprotocol/sdk` 1.32 | MCP connect, tools, errors |

It prints a fault matrix of what each library catches. Things it found:

- `openid-client` does not verify the ID token signature by default; a tampered token or unknown `kid` passes. `enableNonRepudiationChecks()` fixes it.
- `node-saml` checks `idpIssuer` only on logout messages, never on the login response.
- No library tested rejects SHA-1 signatures, a missing NameID, or a missing email claim. Your app has to.
- `openid-client` refetches the JWKS on an unknown `kid` at most once a minute, so for up to 60 s after a key rotation a long-lived client fails. `go-oidc` refetches at once.
- `node-saml` cannot check `InResponseTo` on a logout reply sent by POST; use the Redirect binding (mock-idp answers in the binding the request used).

Edge cases covered too: IdP-initiated SSO, POST-binding requests, single logout in both bindings, RelayState, ForceAuthn, the IdP session and `prompt=none`, `form_post`, implicit flow, `client_secret_post`, client credentials, logout redirects, single-use codes, PKCE mismatch, key rotation, non-ASCII and guest names, parallel sign-ins across tenants, and latency.

`interop/platform.sh` checks the Docker image: the race detector, API-token mode, state surviving restarts, and hostile input (bad JSON, 2 MB bodies, path traversal, XML bombs, malformed SAML).

Run against the Docker container: `MOCKIDP_URL=http://localhost:7070 interop/run.sh`

## Not yet

Encrypted assertions, signed AuthnRequest verification, inbound SCIM (the IdP as a SCIM server), WS-Fed. Open an issue if you need one.

This is a test tool. Never point production at it.
