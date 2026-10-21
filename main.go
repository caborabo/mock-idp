// mock-idp simulates enterprise identity providers (Okta, Entra ID, Google
// Workspace, OneLogin, PingOne, JumpCloud, AD FS, Auth0, Keycloak) over SAML,
// OIDC and SCIM, with a dashboard, a JSON API and an MCP endpoint.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := flag.String("addr", env("MOCKIDP_ADDR", ":7070"), "listen address")
	baseURL := flag.String("base-url", env("MOCKIDP_BASE_URL", ""), "URL browsers use to reach this server (default http://localhost:<port>)")
	data := flag.String("data", env("MOCKIDP_DATA", "mockidp-data.json"), "state file; empty keeps everything in memory")
	flag.Parse()

	base := strings.TrimRight(*baseURL, "/")
	if base == "" {
		_, port, err := net.SplitHostPort(*addr)
		if err != nil {
			log.Fatalf("bad -addr %q: %v", *addr, err)
		}
		base = "http://localhost:" + port
	}
	s, err := newServer(base, *data, os.Getenv("MOCKIDP_API_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mock-idp %s listening on %s", version, *addr)
	log.Printf("  dashboard  %s", base)
	log.Printf("  API        %s/api", base)
	log.Printf("  MCP        %s/mcp", base)
	log.Fatal(http.ListenAndServe(*addr, s))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
