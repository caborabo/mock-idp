package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
)

// The MCP endpoint (streamable HTTP, JSON responses only) exposes every API
// route as a tool, so an agent gets the same control as the dashboard.

const mcpInstructions = `mock-idp simulates enterprise identity providers (Okta, Entra ID, Google Workspace, OneLogin, PingOne, JumpCloud, AD FS, Auth0, Keycloak) over SAML, OIDC and SCIM, for testing an app's SSO and provisioning.
Typical loop: list_tenants → get_endpoints (configure the app under test with these) → set_simulations or apply_preset to inject a fault → have the app sign in (or use mint_tokens / make_saml_response headlessly) → list_logs to see exactly what was sent and why → reset_simulations.
Set autoLogin in set_simulations to a userName to skip the login page in automated browser tests. get_info lists every provider quirk and simulation.`

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if err := s.localOnly(r); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	var req rpcReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
		return
	}
	if len(req.ID) == 0 { // a notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	reply := func(result any) { writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result}) }
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = "2025-06-18"
		}
		reply(map[string]any{"protocolVersion": p.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{"name": "mock-idp", "version": version}, "instructions": mcpInstructions})
	case "ping":
		reply(map[string]any{})
	case "tools/list":
		reply(map[string]any{"tools": s.mcpTools()})
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		json.Unmarshal(req.Params, &p)
		text, isErr := s.mcpCall(r, p.Name, p.Arguments)
		reply(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr})
	default:
		writeJSON(w, 200, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32601, "message": "method not found: " + req.Method}})
	}
}

func (s *Server) mcpTools() []map[string]any {
	var tools []map[string]any
	for _, rt := range s.routes {
		props := map[string]any{}
		required := []string{}
		for _, m := range pathParam.FindAllStringSubmatch(rt.Path, -1) {
			props[m[1]] = map[string]any{"type": "string", "description": paramDesc[m[1]]}
			required = append(required, m[1])
		}
		for _, q := range rt.Query {
			props[q] = map[string]any{"type": "string"}
		}
		if rt.Body != nil {
			ex, _ := json.Marshal(rt.Body)
			props["body"] = map[string]any{"type": "object", "description": "JSON body. Example: " + string(ex)}
		}
		tools = append(tools, map[string]any{"name": rt.Name, "description": rt.Desc + " (" + rt.Method + " " + rt.Path + ")",
			"inputSchema": map[string]any{"type": "object", "properties": props, "required": required}})
	}
	return tools
}

var paramDesc = map[string]string{
	"tenant": "tenant id, e.g. okta or entra (see list_tenants)",
	"user":   "user id, userName or email",
	"group":  "group id or name",
	"app":    "app id, e.g. test-saml or test-oidc",
	"target": "SCIM target id",
	"preset": "preset key from get_info",
	"id":     "log entry id",
}

// mcpCall runs the tool's route in-process and returns the response body.
func (s *Server) mcpCall(r *http.Request, name string, args map[string]any) (string, bool) {
	for _, rt := range s.routes {
		if rt.Name != name {
			continue
		}
		missing := ""
		path := pathParam.ReplaceAllStringFunc(rt.Path, func(m string) string {
			v := fmt.Sprint(args[m[1:len(m)-1]])
			if args[m[1:len(m)-1]] == nil {
				missing = m
			}
			return url.PathEscape(v)
		})
		if missing != "" {
			return "missing argument " + missing, true
		}
		q := url.Values{}
		for _, k := range rt.Query {
			if v, ok := args[k]; ok {
				q.Set(k, fmt.Sprint(v))
			}
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		var body []byte
		if b, ok := args["body"]; ok {
			body, _ = json.Marshal(b)
		}
		req := httptest.NewRequest(rt.Method, path, bytes.NewReader(body))
		req.Host = r.Host // already passed localOnly; keep it so the inner call does too
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", r.Header.Get("Authorization"))
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		return rec.Body.String(), rec.Code >= 400
	}
	return "unknown tool " + name, true
}

func (s *Server) llmsTxt(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	fmt.Fprintf(&b, "# mock-idp\n\n%s\n\nBase URL: %s\nMCP (streamable HTTP): %s/mcp\nAdd to Claude Code: claude mcp add --transport http mock-idp %s/mcp\n\n## API\n\n", mcpInstructions, s.base, s.base, s.base)
	for _, rt := range s.routes {
		fmt.Fprintf(&b, "- %s %s — %s", rt.Method, rt.Path, rt.Desc)
		if rt.Body != nil {
			ex, _ := json.Marshal(rt.Body)
			fmt.Fprintf(&b, " Body: %s", ex)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n## IdP endpoints (per tenant)\n\n- OIDC: /t/{tenant}/.well-known/openid-configuration, /authorize, /token, /userinfo, /jwks, /logout\n- SAML: /t/{tenant}/saml/{app}/metadata, /sso (Redirect and POST), /init (IdP-initiated), /slo\n- Built-in test SP: /sp/saml/{tenant}/{app}/login, test RP: /sp/oidc/{tenant}/{app}/login\n")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(b.String()))
}
