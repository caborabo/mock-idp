# Security policy

mock-idp is a test tool. It is meant to be insecure in controlled ways: it signs in anyone, publishes test secrets, and forges bad responses on purpose. Never run it in production or expose it to the internet.

## What counts as a vulnerability

Please report problems that hurt the machine or network mock-idp runs on, such as:

- A web page you visit can drive your local mock-idp (cross-site requests, DNS rebinding) despite the built-in guard.
- `MOCKIDP_API_TOKEN` can be bypassed.
- Input to the IdP endpoints, the API or MCP can read or write files, run code, or crash the process (path traversal, XML bombs and so on).
- The Docker image runs as root or ships something it should not.

Not vulnerabilities: anything the simulations do on purpose, the seeded demo passwords and client secrets, and the IdP endpoints under `/t/` being open to any host.

## How to report

Use GitHub's **Report a vulnerability** button on the Security tab of this repository, or email support@ssojet.com with "mock-idp security" in the subject.

Include the version or commit, how to reproduce it, and what an attacker gains. We aim to reply within 3 working days. Please don't open a public issue until a fix is released.

## Supported versions

Only the latest release and `main` get security fixes.
