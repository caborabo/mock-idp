# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

First public version.

- 9 simulated identity providers with their quirks: Okta, Entra ID, Google Workspace, OneLogin, PingOne, JumpCloud, AD FS, Auth0, Keycloak, plus a generic one.
- SAML 2.0 IdP: metadata, SP- and IdP-initiated SSO, Redirect and POST bindings, single logout.
- Encrypted assertions (AES-128/256 CBC or GCM, RSA-OAEP or RSA 1.5) and signed AuthnRequest verification.
- OIDC provider: discovery, JWKS, code + PKCE, implicit, refresh, client credentials, password grant, userinfo, logout.
- SCIM client with Okta and Entra dialects, auto-push, full sync and a conformance suite.
- 40 simulations, presets, and `once` to clear faults after the next sign-in.
- Built-in test SP and RP that show every check they ran.
- Live logs with decoded SAML and JWTs.
- JSON API, MCP server and `/llms.txt`.
- Interop tests against node-saml, crewjam/saml, openid-client, go-oidc and the MCP SDK.
- Multi-arch Docker image on GHCR.
