#!/usr/bin/env bash
# Platform checks on the Docker image: race detector, API token mode,
# persistence across restarts, and hostile input. Needs Docker.
# Usage: interop/platform.sh
set -uo pipefail
cd "$(dirname "$0")/.."
IMG=mock-idp:platform-test
PORT=7474
fails=0
pass() { echo "  ✔ $1"; }
fail() { echo "  ✖ $1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
up() { for _ in $(seq 40); do curl -sf "localhost:$PORT/api/info" -H "Authorization: Bearer ${TOKEN:-}" >/dev/null && return; sleep 0.25; done; }
cleanup() { docker rm -f mockidp-platform >/dev/null 2>&1; docker volume rm -f mockidp-platform >/dev/null 2>&1; }
trap cleanup EXIT

echo "race detector (go test -race)"
check "unit and flow tests pass under -race" "go test -race -count=1 ./... >/tmp/mockidp-race.log 2>&1"

docker build -q -t "$IMG" . >/dev/null || { echo "docker build failed"; exit 1; }

echo "API token mode"
cleanup
TOKEN=s3cret
docker run -d --name mockidp-platform -p $PORT:7070 -e MOCKIDP_API_TOKEN=$TOKEN -e MOCKIDP_BASE_URL=http://localhost:$PORT "$IMG" >/dev/null
up
check "API without token is 401" '[ "$(code localhost:$PORT/api/tenants)" = 401 ]'
check "API with wrong token is 401" '[ "$(code -H "Authorization: Bearer nope" localhost:$PORT/api/tenants)" = 401 ]'
check "API with token is 200" '[ "$(code -H "Authorization: Bearer $TOKEN" localhost:$PORT/api/tenants)" = 200 ]'
check "MCP without token is 401" '[ "$(code -X POST -d "{}" localhost:$PORT/mcp)" = 401 ]'
check "MCP with token works" 'curl -s -X POST -H "Authorization: Bearer $TOKEN" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" localhost:$PORT/mcp | grep -q list_tenants'
check "log stream without token is 401" '[ "$(code -m 2 localhost:$PORT/api/logs/stream)" = 401 ]'
check "log stream with ?token= connects" '{ curl -s -m 2 "localhost:$PORT/api/logs/stream?token=$TOKEN" || true; } | grep -q connected'
check "IdP endpoints stay public (apps must reach them)" '[ "$(code localhost:$PORT/t/okta/.well-known/openid-configuration)" = 200 ]'
check "dashboard page stays public" '[ "$(code localhost:$PORT/)" = 200 ]'
TOKEN=

echo "persistence"
cleanup
docker run -d --name mockidp-platform -p $PORT:7070 -v mockidp-platform:/data "$IMG" >/dev/null
up
curl -s -X POST localhost:$PORT/api/tenants -d '{"name":"Persist Me","provider":"entra"}' >/dev/null
curl -s -X PATCH localhost:$PORT/api/tenants/persist-me/simulations -d '{"samlExpired":true}' >/dev/null
KID=$(curl -s localhost:$PORT/api/tenants/persist-me/endpoints | grep -o '"kid": "[^"]*"')
docker restart mockidp-platform >/dev/null
up
check "tenant survives a restart" 'curl -s localhost:$PORT/api/tenants | grep -q persist-me'
check "simulations survive a restart" 'curl -s localhost:$PORT/api/tenants/persist-me/simulations | grep -q "\"samlExpired\": true"'
check "signing key survives a restart (apps keep trusting it)" '[ "$(curl -s localhost:$PORT/api/tenants/persist-me/endpoints | grep -o "\"kid\": \"[^\"]*\"")" = "$KID" ]'
check "no permission errors in the log" '! docker logs mockidp-platform 2>&1 | grep -qi denied'

echo "hostile input"
check "invalid JSON is 400 JSON, not a crash" 'curl -s -X POST localhost:$PORT/api/tenants -d "{nope" | grep -q "bad JSON body"'
check "unknown provider is 400" '[ "$(code -X POST localhost:$PORT/api/tenants -d "{\"provider\":\"myspace\"}")" = 400 ]'
check "2 MB body is refused cleanly" '[ "$(head -c 2000000 /dev/zero | tr "\0" a | code -X POST localhost:$PORT/api/decode --data-binary @-)" = 400 ]'
check "path traversal on static files is refused" '[ "$(code --path-as-is "localhost:$PORT/../../etc/passwd")" != 200 ]'
check "garbage SAMLRequest is 400" '[ "$(code "localhost:$PORT/t/okta/saml/test-saml/sso?SAMLRequest=%%%")" = 400 ]'
check "XML bomb in SAMLRequest is refused fast" '[ "$(printf "<!DOCTYPE x [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]><samlp:AuthnRequest>&c;</samlp:AuthnRequest>" | base64 | tr -d "\n" | xargs -I{} curl -s -o /dev/null -w "%{http_code}" -m 5 --data-urlencode "SAMLRequest={}" localhost:$PORT/t/okta/saml/test-saml/sso)" = 400 ]'
check "unknown tenant on the IdP is 404" '[ "$(code localhost:$PORT/t/nope/.well-known/openid-configuration)" = 404 ]'
check "authorize with an unknown client never redirects" '[ "$(code "localhost:$PORT/t/okta/authorize?client_id=x&redirect_uri=https://evil.example")" = 400 ]'
check "MCP garbage is a JSON-RPC parse error" 'curl -s -X POST localhost:$PORT/mcp -d "not json" | grep -q -- "-32700"'
check "server still healthy after all of that" '[ "$(code localhost:$PORT/api/info)" = 200 ]'

echo
[ $fails = 0 ] && echo "platform: all checks passed" || echo "platform: $fails check(s) failed"
exit $fails
