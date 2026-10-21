package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	ts := httptest.NewUnstartedServer(nil)
	s, err := newServer("http://"+ts.Listener.Addr().String(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = s
	ts.Start()
	t.Cleanup(ts.Close)
	return s, ts
}

func call(t *testing.T, ts *httptest.Server, method, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(string(b)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

var (
	formAction = regexp.MustCompile(`action="([^"]+)"`)
	formInput  = regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`)
)

// browse follows redirects and auto-POST forms like a browser and returns
// the final page.
func browse(t *testing.T, start string) string {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(start)
	for i := 0; i < 5; i++ {
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		page := string(b)
		if !strings.Contains(page, "document.forms[0].submit()") {
			return page
		}
		form := url.Values{}
		for _, m := range formInput.FindAllStringSubmatch(page, -1) {
			form.Set(m[1], html.UnescapeString(m[2]))
		}
		resp, err = c.PostForm(html.UnescapeString(formAction.FindStringSubmatch(page)[1]), form)
	}
	t.Fatal("too many auto-posts")
	return ""
}

func TestSAMLAndOIDCThroughBuiltInApps(t *testing.T) {
	_, ts := newTestServer(t)
	for _, tc := range []struct{ tenant, domain string }{{"okta", "acme.example"}, {"entra", "contoso.example"}, {"google", "globex.example"}, {"adfs", "wayne.example"}, {"keycloak", "cyberdyne.example"}} {
		call(t, ts, "PATCH", "/api/tenants/"+tc.tenant+"/simulations", map[string]any{"autoLogin": "alice@" + tc.domain})
		if page := browse(t, ts.URL+"/sp/saml/"+tc.tenant+"/test-saml/login"); !strings.Contains(page, "✓</span> Signed in") {
			t.Errorf("%s SAML: not signed in:\n%s", tc.tenant, page)
		}
		if page := browse(t, ts.URL+"/sp/oidc/"+tc.tenant+"/test-oidc/login"); !strings.Contains(page, "✓</span> Signed in") {
			t.Errorf("%s OIDC: not signed in:\n%s", tc.tenant, page)
		}
	}

	// every fault must make the careful test app reject the sign-in
	for _, sim := range []string{"samlExpired", "samlBadSignature", "samlWrongCert", "samlUnsigned", "samlSignatureWrapping", "samlCommentInjection",
		"samlWrongAudience", "samlWrongIssuer", "samlWrongInResponseTo", "samlNotYetValid", "samlWrongRecipient", "samlWrongDestination", "samlMissingNameId"} {
		call(t, ts, "PATCH", "/api/tenants/okta/simulations", map[string]any{sim: true, "once": true})
		if page := browse(t, ts.URL+"/sp/saml/okta/test-saml/login"); !strings.Contains(page, "Rejected") {
			t.Errorf("SAML %s was accepted", sim)
		}
	}
	for _, sim := range []string{"oidcExpired", "oidcBadSignature", "oidcAlgNone", "oidcUnknownKid", "oidcWrongNonce", "oidcWrongAudience", "oidcWrongIssuer", "oidcWrongAtHash", "oidcWrongState"} {
		call(t, ts, "PATCH", "/api/tenants/okta/simulations", map[string]any{sim: true, "once": true})
		if page := browse(t, ts.URL+"/sp/oidc/okta/test-oidc/login"); !strings.Contains(page, "Rejected") {
			t.Errorf("OIDC %s was accepted", sim)
		}
	}
	// once cleared them: a normal sign-in works again
	if page := browse(t, ts.URL+"/sp/oidc/okta/test-oidc/login"); !strings.Contains(page, "✓</span> Signed in") {
		t.Errorf("once did not clear the faults")
	}
}

func TestCatalogMatchesSimulations(t *testing.T) {
	var tags []string
	ty := reflect.TypeOf(Simulations{})
	for i := 0; i < ty.NumField(); i++ {
		tags = append(tags, ty.Field(i).Tag.Get("json"))
	}
	for _, c := range simCatalog {
		if !slices.Contains(tags, c.Key) {
			t.Errorf("catalog key %q is not a Simulations field", c.Key)
		}
	}
	if len(simCatalog) != len(tags) {
		t.Errorf("catalog has %d entries, Simulations has %d fields", len(simCatalog), len(tags))
	}
}

func TestMCP(t *testing.T) {
	_, ts := newTestServer(t)
	rpc := func(method string, params any) map[string]any {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return m["result"].(map[string]any)
	}
	if tools := rpc("tools/list", nil)["tools"].([]any); len(tools) < 30 {
		t.Fatalf("only %d tools", len(tools))
	}
	res := rpc("tools/call", map[string]any{"name": "apply_preset", "arguments": map[string]any{"tenant": "entra", "preset": "expired"}})
	if res["isError"] == true || !strings.Contains(fmt.Sprint(res["content"]), `"samlExpired": true`) {
		t.Fatalf("apply_preset: %v", res)
	}
}

// scimServer is a small, correct SCIM 2.0 server that accepts both the Okta
// and the Entra dialects.
func scimServer() *httptest.Server {
	var mu sync.Mutex
	users := map[string]map[string]any{}
	groups := map[string]map[string]any{}
	n := 0
	scim := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	notFound := func(w http.ResponseWriter) {
		scim(w, 404, map[string]any{"schemas": []string{schemaError}, "status": "404"})
	}
	filterRe := regexp.MustCompile(`^(\w+) eq "(.*)"$`)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		store, key := users, "userName"
		if parts[0] == "Groups" {
			store, key = groups, "displayName"
		}
		if parts[0] == "ServiceProviderConfig" {
			scim(w, 200, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}})
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if len(parts) == 1 {
			if r.Method == "POST" {
				for _, u := range store {
					if strings.EqualFold(str(u[key]), str(body[key])) {
						scim(w, 409, map[string]any{"schemas": []string{schemaError}, "status": "409"})
						return
					}
				}
				n++
				body["id"] = fmt.Sprint(n)
				store[body["id"].(string)] = body
				scim(w, 201, body)
				return
			}
			res := []any{}
			m := filterRe.FindStringSubmatch(r.URL.Query().Get("filter"))
			for _, u := range store {
				if m == nil || strings.EqualFold(str(u[m[1]]), m[2]) {
					res = append(res, u)
				}
			}
			if r.URL.Query().Get("count") == "1" && len(res) > 1 {
				res = res[:1]
			}
			scim(w, 200, map[string]any{"schemas": []string{schemaList}, "totalResults": len(res), "Resources": res})
			return
		}
		obj := store[parts[1]]
		if obj == nil {
			notFound(w)
			return
		}
		switch r.Method {
		case "GET":
			scim(w, 200, obj)
		case "DELETE":
			delete(store, parts[1])
			w.WriteHeader(204)
		case "PUT":
			body["id"] = parts[1]
			store[parts[1]] = body
			scim(w, 200, body)
		case "PATCH":
			ops, _ := body["Operations"].([]any)
			for _, o := range ops {
				op := o.(map[string]any)
				name, path := strings.ToLower(str(op["op"])), str(op["path"])
				val := op["value"]
				if s, ok := val.(string); ok && (s == "True" || s == "False") {
					val = s == "True"
				}
				switch {
				case path == "" && name == "replace":
					for k, v := range val.(map[string]any) {
						obj[k] = v
					}
				case path == "members" && name == "add":
					ms, _ := obj["members"].([]any)
					obj["members"] = append(ms, val.([]any)...)
				case path == "members" && name == "remove":
					drop := memberIDs(map[string]any{"members": val})
					ms, _ := obj["members"].([]any)
					obj["members"] = slices.DeleteFunc(ms, func(m any) bool { return slices.Contains(drop, str(m.(map[string]any)["value"])) })
				case strings.HasPrefix(path, "members[value eq "):
					id := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(path, "members[value eq "), "]"), `"`)
					ms, _ := obj["members"].([]any)
					obj["members"] = slices.DeleteFunc(ms, func(m any) bool { return str(m.(map[string]any)["value"]) == id })
				case strings.HasPrefix(path, "name."):
					nm, _ := obj["name"].(map[string]any)
					if nm == nil {
						nm = map[string]any{}
					}
					nm[strings.TrimPrefix(path, "name.")] = val
					obj["name"] = nm
				case !strings.ContainsAny(path, "[:"):
					obj[path] = val
				}
			}
			scim(w, 200, obj)
		}
	}))
}

func TestScimConformanceBothDialects(t *testing.T) {
	_, ts := newTestServer(t)
	app := scimServer()
	defer app.Close()
	call(t, ts, "POST", "/api/tenants/entra/scim-targets", map[string]any{"name": "app", "baseUrl": app.URL, "token": "x"})
	for _, flavor := range []string{"entra", "okta"} {
		run := call(t, ts, "POST", "/api/tenants/entra/scim-targets/app/conformance", map[string]any{"flavor": flavor})
		if run["failed"].(float64) != 0 {
			t.Errorf("%s flavor: %v", flavor, run["checks"])
		}
	}
	run := call(t, ts, "POST", "/api/tenants/entra/scim-targets/app/sync", nil)
	if run["failed"].(float64) != 0 {
		t.Errorf("sync: %v", run["checks"])
	}
	// deactivating a user pushes active=false as Entra does ("False")
	call(t, ts, "PATCH", "/api/tenants/entra/scim-targets/app", map[string]any{"autoPush": true})
	run = call(t, ts, "POST", "/api/tenants/entra/scim-targets/app/push", map[string]any{"kind": "user", "id": "bob@contoso.example", "action": "deactivate"})
	if run["failed"].(float64) != 0 {
		t.Errorf("push: %v", run["checks"])
	}
}

// A web page must not be able to drive a mock-idp on a developer's machine,
// by a cross-site request or by DNS rebinding. Non-browser clients must.
func TestBrowsersCannotDriveTheAPI(t *testing.T) {
	s, _ := newTestServer(t)
	try := func(method, path, host, origin string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}
	const preset = "/api/tenants/okta/simulations/presets/outage"
	for _, c := range []struct {
		name, method, path, host, origin string
		want                             int
	}{
		{"cross-site POST from a web page", "POST", preset, "localhost:7070", "https://evil.example", 403},
		{"sandboxed page (Origin null)", "POST", preset, "localhost:7070", "null", 403},
		{"DNS rebinding: hostile name, same-origin", "GET", "/api/tenants", "evil.example:7070", "http://evil.example:7070", 403},
		{"DNS rebinding, no Origin on a GET", "GET", "/api/tenants", "evil.example:7070", "", 403},
		{"rebinding against MCP", "POST", "/mcp", "evil.example:7070", "http://evil.example:7070", 403},
		{"the dashboard itself", "POST", preset, "localhost:7070", "http://localhost:7070", 200},
		{"dashboard opened at 127.0.0.1", "GET", "/api/tenants", "127.0.0.1:7070", "http://127.0.0.1:7070", 200},
		{"curl / scripts / agents (no Origin)", "POST", preset, "localhost:7070", "", 200},
		{"another compose service", "GET", "/api/tenants", "mock-idp:7070", "", 200},
		{"from another container", "GET", "/api/tenants", "host.docker.internal:7070", "", 200},
		{"IdP endpoints stay open to any host", "GET", "/t/entra/jwks", "idp.company.test", "https://app.company.test", 200},
	} {
		if got := try(c.method, c.path, c.host, c.origin); got != c.want {
			t.Errorf("%s: HTTP %d, want %d", c.name, got, c.want)
		}
	}
	// MCP tool calls go through the API in-process and must still pass.
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tenants","arguments":{}}}`))
	req.Host = "localhost:7070"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Errorf("MCP tool call blocked: %s", rec.Body.String())
	}
}
