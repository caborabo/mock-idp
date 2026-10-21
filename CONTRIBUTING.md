# Contributing to mock-idp

Thanks for helping. Bug reports, new provider quirks, new faults and library findings are all welcome.

## Quick start

You need Go 1.24+ and Node 24 (Node only for the interop tests).

```bash
go run .
```

Open http://localhost:7070. Change a file under `web/` and reload; there is no build step.

## Before you open a pull request

Run the same checks CI runs:

```bash
go vet ./...
```

```bash
go test -race -count=1 ./...
```

```bash
interop/run.sh
```

`interop/run.sh` starts a fresh mock-idp and runs real libraries against it: node-saml, openid-client, crewjam/saml, go-oidc and the MCP SDK. If you have Docker, `interop/platform.sh` checks the image too.

## Where things live

| You want to… | Look in |
|---|---|
| Add or fix a provider quirk | `providers.go` (`providerList`) |
| Add a fault | `sims.go` (the `Simulations` struct and the catalogue), then apply it in `saml.go` or `oidc.go` |
| Change the SAML IdP | `saml.go`, `xmlenc.go` |
| Change the OIDC provider | `oidc.go` |
| Change the login pages | `login.go`, `pages.go` |
| Change the built-in test SP / RP | `sp.go` |
| Change SCIM provisioning | `scim.go` |
| Add an API route (it becomes an MCP tool too) | `api.go` |
| Change the dashboard | `web/` |

## Adding a fault

1. Add a field to `Simulations` and an entry to the catalogue in `sims.go`. Write the description so a person knows what their app should do.
2. Apply it where the IdP builds the response. Log it with `entry(r).warn(...)` so it shows in Live logs.
3. Make the built-in test SP or RP catch it in `sp.go`, if a careful app should.
4. Add a test in `main_test.go`. If a real library should reject it, add it to the fault lists in `interop/`.

## Adding a provider quirk

Quirks must come from the real provider's behaviour. Link to the vendor docs, or describe what you saw, in the pull request. Add one plain line to `Quirks` so it shows on the tenant page.

## Style

- Keep dependencies at two: `beevik/etree` and `russellhaering/goxmldsig`. Ask in an issue before adding one.
- The dashboard is plain JavaScript. No framework, no bundler.
- Error messages and UI text: short, plain words, and say what to do next.
- Commit messages: `area: what changed`, e.g. `saml: verify signed AuthnRequests`.

## Reporting a library finding

Found a client library that accepts something it should reject? Open an issue with the library, its version, the fault key and what happened. We add confirmed findings to the README's report card.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
