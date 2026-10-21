package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaEnt   = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// ScimRun is the outcome of a test, sync, push or conformance run. Each
// check links to the log entry of the HTTP call behind it.
type ScimRun struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Flavor string    `json:"flavor"`
	Run    string    `json:"run"`
	Checks []check   `json:"checks"`
	Passed int       `json:"passed"`
	Failed int       `json:"failed"`
	Warned int       `json:"warned"`
}

// scimClient plays the IdP's provisioning engine against an app's SCIM
// server. It works on a snapshot so the store is not locked during HTTP.
type scimClient struct {
	s         *Server
	tenant    string
	target    ScimTarget
	flavor    ScimFlavor
	flavorKey string
	users     map[string]User
	groups    []Group
	run       string
	http      *http.Client
}

func (s *Server) newScimClient(tid, targetID, flavor string) (*scimClient, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.store.tenant(tid)
	if t == nil {
		return nil, errf(404, "unknown tenant %s", tid)
	}
	tg := t.target(targetID)
	if tg == nil {
		return nil, errf(404, "unknown SCIM target %s", targetID)
	}
	key := flavor
	if key == "" {
		key = tg.Flavor
	}
	if key == "" {
		key = t.Provider
	}
	p := providers[key]
	if p == nil {
		return nil, errf(400, "unknown flavor %q", key)
	}
	c := &scimClient{s: s, tenant: tid, target: *tg, flavor: p.Scim, flavorKey: key, users: map[string]User{},
		run: randHex(6), http: &http.Client{Timeout: 15 * time.Second}}
	c.target.UserMap = maps.Clone(tg.UserMap)
	c.target.GroupMap = maps.Clone(tg.GroupMap)
	if c.target.UserMap == nil {
		c.target.UserMap = map[string]string{}
	}
	if c.target.GroupMap == nil {
		c.target.GroupMap = map[string]string{}
	}
	for _, u := range t.Users {
		c.users[u.ID] = *u
	}
	for _, g := range t.Groups {
		c.groups = append(c.groups, Group{ID: g.ID, Name: g.Name, Members: slices.Clone(g.Members)})
	}
	return c, nil
}

// finish stores the id maps and the run summary on the target.
func (c *scimClient) finish(kind string, cs []check) *ScimRun {
	run := &ScimRun{Time: time.Now().UTC(), Kind: kind, Flavor: c.flavorKey, Run: c.run, Checks: cs}
	for _, x := range cs {
		switch x.Result {
		case "pass":
			run.Passed++
		case "fail":
			run.Failed++
		default:
			run.Warned++
		}
	}
	c.s.store.mu.Lock()
	if t := c.s.store.tenant(c.tenant); t != nil {
		if tg := t.target(c.target.ID); tg != nil {
			tg.UserMap, tg.GroupMap, tg.LastResult = c.target.UserMap, c.target.GroupMap, run
			c.s.store.save()
		}
	}
	c.s.store.mu.Unlock()
	c.s.logs.publish("change", map[string]string{"tenant": c.tenant})
	return run
}

type scimResp struct {
	status int
	body   map[string]any
	ctype  string
	log    int64
	err    error
}

func (c *scimClient) call(method, path string, body any, summary string) scimResp {
	u := strings.TrimRight(c.target.BaseURL, "/") + path
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.MarshalIndent(body, "", "  ")
	}
	e := &LogEntry{Kind: "scim.out", Level: "info", Tenant: c.tenant, Method: method, URL: u, ReqBody: string(reqBody), Run: c.run,
		Summary: "SCIM " + method + " " + path + ": " + summary}
	req, err := http.NewRequest(method, u, bytes.NewReader(reqBody))
	if err != nil {
		e.fail("%v", err)
		c.s.logs.add(e)
		return scimResp{err: err, log: e.ID}
	}
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
	}
	req.Header.Set("User-Agent", "mock-idp/"+version+" ("+providers[c.flavorKey].Name+" SCIM flavor)")
	if tok := c.target.Token; tok != "" {
		if !strings.HasPrefix(tok, "Bearer ") && !strings.HasPrefix(tok, "Basic ") {
			tok = "Bearer " + tok
		}
		req.Header.Set("Authorization", tok)
	}
	e.ReqHeaders = req.Header.Clone()
	start := time.Now()
	resp, err := c.http.Do(req)
	e.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		e.fail("request failed: %v", err)
		c.s.logs.add(e)
		return scimResp{err: err, log: e.ID}
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	e.Status, e.RespHeaders, e.RespBody = resp.StatusCode, resp.Header.Clone(), string(rb)
	if resp.StatusCode >= 400 {
		e.Level = "error"
	}
	var m map[string]any
	json.Unmarshal(rb, &m)
	c.s.logs.add(e)
	return scimResp{status: resp.StatusCode, body: m, ctype: resp.Header.Get("Content-Type"), log: e.ID}
}

func (c *scimClient) op(name, path string, value any) map[string]any {
	if c.flavor.OpCase == "title" {
		name = strings.ToUpper(name[:1]) + name[1:]
	}
	m := map[string]any{"op": name}
	if path != "" {
		m["path"] = path
	}
	if value != nil {
		m["value"] = value
	}
	return m
}

func (c *scimClient) boolean(b bool) any {
	if c.flavor.BoolStrings {
		return map[bool]string{true: "True", false: "False"}[b]
	}
	return b
}

func patchBody(ops ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{schemaPatch}, "Operations": ops}
}

func (c *scimClient) userResource(u User) map[string]any {
	schemas := []string{schemaUser}
	r := map[string]any{
		"userName":    u.UserName,
		"name":        map[string]any{"givenName": u.GivenName, "familyName": u.FamilyName, "formatted": u.DisplayName},
		"displayName": u.DisplayName,
		"active":      u.Active,
	}
	if u.Email != "" {
		r["emails"] = []any{map[string]any{"value": u.Email, "type": "work", "primary": true}}
	}
	switch c.flavorKey {
	case "entra":
		r["externalId"] = strings.Split(u.UserName, "@")[0] // mailNickname
	case "okta":
	default:
		r["externalId"] = u.ID
	}
	if u.Title != "" {
		r["title"] = u.Title
	}
	if u.Phone != "" {
		r["phoneNumbers"] = []any{map[string]any{"value": u.Phone, "type": "work"}}
	}
	if u.Department != "" || u.EmployeeNumber != "" || u.Manager != "" {
		ent := map[string]any{}
		if u.Department != "" {
			ent["department"] = u.Department
		}
		if u.EmployeeNumber != "" {
			ent["employeeNumber"] = u.EmployeeNumber
		}
		if m := c.target.UserMap[u.Manager]; m != "" {
			ent["manager"] = map[string]any{"value": m}
		}
		schemas = append(schemas, schemaEnt)
		r[schemaEnt] = ent
	}
	r["schemas"] = schemas
	return r
}

func (c *scimClient) deactivateOp() map[string]any {
	if c.flavor.Update == "PUT" { // Okta style: no path, an object value
		return patchBody(c.op("replace", "", map[string]any{"active": false}))
	}
	return patchBody(c.op("replace", "active", c.boolean(false)))
}

func (c *scimClient) updateBody(u User, id string) (string, map[string]any) {
	if c.flavor.Update == "PUT" {
		r := c.userResource(u)
		r["id"] = id
		return "PUT", r
	}
	ops := []map[string]any{
		c.op("replace", "displayName", u.DisplayName),
		c.op("replace", "name.givenName", u.GivenName),
		c.op("replace", "name.familyName", u.FamilyName),
		c.op("replace", "active", c.boolean(u.Active)),
	}
	if u.Email != "" {
		ops = append(ops, c.op("replace", `emails[type eq "work"].value`, u.Email))
	}
	if u.Title != "" {
		ops = append(ops, c.op("replace", "title", u.Title))
	}
	if u.Department != "" {
		ops = append(ops, c.op("replace", schemaEnt+":department", u.Department))
	}
	return "PATCH", patchBody(ops...)
}

func filterQ(attr, v string) string {
	return "?filter=" + url.QueryEscape(fmt.Sprintf(`%s eq "%s"`, attr, v))
}

func firstResourceID(body map[string]any) string {
	res, _ := body["Resources"].([]any)
	if len(res) == 0 {
		return ""
	}
	m, _ := res[0].(map[string]any)
	return str(m["id"])
}

func (c *scimClient) findUser(u User) string {
	if id := c.target.UserMap[u.ID]; id != "" {
		return id
	}
	r := c.call("GET", "/Users"+filterQ("userName", u.UserName), nil, "find "+u.UserName)
	if id := firstResourceID(r.body); r.status == 200 && id != "" {
		c.target.UserMap[u.ID] = id
		return id
	}
	return ""
}

func result(name string, r scimResp, ok bool, detail string, a ...any) check {
	c := check{Name: name, Result: "pass", Detail: fmt.Sprintf(detail, a...), Log: r.log}
	if r.err != nil {
		c.Result, c.Detail = "fail", r.err.Error()
	} else if !ok {
		c.Result = "fail"
	}
	return c
}

func okStatus(code int) bool { return code == 200 || code == 201 || code == 204 }

// pushUser does what the IdP does when a user is assigned, changed or
// removed: action is upsert, deactivate or delete.
func (c *scimClient) pushUser(u User, action string) check {
	name := action + " " + u.UserName
	switch action {
	case "upsert":
		if !u.Active {
			return c.pushUser(u, "deactivate")
		}
		id := c.findUser(u)
		if id == "" {
			r := c.call("POST", "/Users", c.userResource(u), "create "+u.UserName)
			id = str(r.body["id"])
			if id != "" {
				c.target.UserMap[u.ID] = id
			}
			return result(name, r, okStatus(r.status) && id != "", "HTTP %d, remote id %q", r.status, id)
		}
		method, body := c.updateBody(u, id)
		r := c.call(method, "/Users/"+id, body, "update "+u.UserName)
		return result(name, r, okStatus(r.status), "%s → HTTP %d", method, r.status)
	case "deactivate":
		id := c.findUser(u)
		if id == "" {
			return check{Name: name, Result: "warn", Detail: "not on the app; nothing to deactivate"}
		}
		r := c.call("PATCH", "/Users/"+id, c.deactivateOp(), "deactivate "+u.UserName)
		return result(name, r, okStatus(r.status), "HTTP %d", r.status)
	case "delete":
		id := c.findUser(u)
		if id == "" {
			return check{Name: name, Result: "warn", Detail: "not on the app; nothing to delete"}
		}
		var r scimResp
		if strings.Contains(c.flavor.OnDelete, "deactivate") {
			r = c.call("PATCH", "/Users/"+id, c.deactivateOp(), "deactivate "+u.UserName)
		}
		if strings.Contains(c.flavor.OnDelete, "delete") {
			r = c.call("DELETE", "/Users/"+id, nil, "delete "+u.UserName)
			delete(c.target.UserMap, u.ID)
		}
		return result(name, r, okStatus(r.status), "%s: HTTP %d", c.flavor.OnDelete, r.status)
	}
	return check{Name: name, Result: "fail", Detail: "unknown action " + action}
}

func memberIDs(body map[string]any) []string {
	var out []string
	ms, _ := body["members"].([]any)
	for _, m := range ms {
		if mm, ok := m.(map[string]any); ok {
			out = append(out, str(mm["value"]))
		}
	}
	return out
}

func (c *scimClient) removeMemberOps(ids []string) []map[string]any {
	if c.flavor.RemoveMember == "value-array" {
		var vals []any
		for _, id := range ids {
			vals = append(vals, map[string]any{"value": id})
		}
		return []map[string]any{c.op("remove", "members", vals)}
	}
	var ops []map[string]any
	for _, id := range ids {
		ops = append(ops, c.op("remove", fmt.Sprintf(`members[value eq "%s"]`, id), nil))
	}
	return ops
}

// pushGroup creates, updates (membership diff) or deletes a group.
func (c *scimClient) pushGroup(g Group, action string) check {
	name := action + " group " + g.Name
	id := c.target.GroupMap[g.ID]
	if id == "" {
		r := c.call("GET", "/Groups"+filterQ("displayName", g.Name), nil, "find group "+g.Name)
		if id = firstResourceID(r.body); id != "" {
			c.target.GroupMap[g.ID] = id
		}
	}
	if action == "delete" {
		if id == "" {
			return check{Name: name, Result: "warn", Detail: "not on the app"}
		}
		r := c.call("DELETE", "/Groups/"+id, nil, "delete group "+g.Name)
		delete(c.target.GroupMap, g.ID)
		return result(name, r, okStatus(r.status), "HTTP %d", r.status)
	}
	var want []any
	wantIDs := []string{}
	for _, uid := range g.Members {
		u, ok := c.users[uid]
		if !ok || !u.Active {
			continue
		}
		rid := c.target.UserMap[uid]
		if rid == "" {
			c.pushUser(u, "upsert")
			rid = c.target.UserMap[uid]
		}
		if rid != "" {
			want = append(want, map[string]any{"value": rid, "display": u.UserName})
			wantIDs = append(wantIDs, rid)
		}
	}
	if id == "" {
		body := map[string]any{"schemas": []string{schemaGroup}, "displayName": g.Name}
		if c.flavor.MembersOnCreate {
			body["members"] = want
		}
		r := c.call("POST", "/Groups", body, "create group "+g.Name)
		if id = str(r.body["id"]); id == "" || !okStatus(r.status) {
			return result(name, r, false, "HTTP %d, remote id %q", r.status, id)
		}
		c.target.GroupMap[g.ID] = id
		if !c.flavor.MembersOnCreate && len(want) > 0 {
			r = c.call("PATCH", "/Groups/"+id, patchBody(c.op("add", "members", want)), "add members to "+g.Name)
		}
		return result(name, r, okStatus(r.status), "created with %d member(s)", len(want))
	}
	r := c.call("GET", "/Groups/"+id, nil, "read group "+g.Name)
	have := memberIDs(r.body)
	var ops []map[string]any
	if str(r.body["displayName"]) != g.Name {
		ops = append(ops, c.op("replace", "displayName", g.Name))
	}
	var add []any
	for i, rid := range wantIDs {
		if !slices.Contains(have, rid) {
			add = append(add, want[i])
		}
	}
	if len(add) > 0 {
		ops = append(ops, c.op("add", "members", add))
	}
	var gone []string
	for _, rid := range have {
		if !slices.Contains(wantIDs, rid) {
			gone = append(gone, rid)
		}
	}
	if len(gone) > 0 {
		ops = append(ops, c.removeMemberOps(gone)...)
	}
	if len(ops) == 0 {
		return result(name, r, r.status == 200, "already in sync")
	}
	r = c.call("PATCH", "/Groups/"+id, patchBody(ops...), "update group "+g.Name)
	return result(name, r, okStatus(r.status), "+%d −%d member(s): HTTP %d", len(add), len(gone), r.status)
}

func (c *scimClient) sync() []check {
	var out []check
	for _, u := range c.users {
		if u.Active {
			out = append(out, c.pushUser(u, "upsert"))
		} else if c.target.UserMap[u.ID] != "" {
			out = append(out, c.pushUser(u, "deactivate"))
		}
	}
	for _, g := range c.groups {
		out = append(out, c.pushGroup(g, "upsert"))
	}
	return out
}

// test is the provider's "Test connection" button.
func (c *scimClient) test() []check {
	var out []check
	if c.flavor.Probe == "random-filter" {
		r := c.call("GET", "/Users"+filterQ("userName", newUUID()), nil, "connection test: filter for a random userName")
		out = append(out, result("Connection test", r, r.status == 200 && num(r.body["totalResults"]) == 0,
			"HTTP %d, totalResults %v. Entra wants 200 with totalResults 0.", r.status, r.body["totalResults"]))
	} else {
		r := c.call("GET", "/Users?startIndex=1&count=1", nil, "connection test: list one user")
		out = append(out, result("Connection test", r, r.status == 200, "HTTP %d", r.status))
	}
	return out
}

func hasSchema(body map[string]any, schema string) bool {
	ss, _ := body["schemas"].([]any)
	return slices.ContainsFunc(ss, func(v any) bool { return str(v) == schema })
}

// conformance runs the calls this provider makes, plus the edge cases they
// hit in production, against a throwaway user and group.
func (c *scimClient) conformance() []check {
	var out []check
	add := func(ch check) { out = append(out, ch) }
	soft := func(ch check) {
		if ch.Result == "fail" {
			ch.Result = "warn"
		}
		out = append(out, ch)
	}
	uname := "mockidp." + randHex(4) + "@example.com"

	r := c.call("GET", "/ServiceProviderConfig", nil, "conformance: discovery")
	soft(result("GET /ServiceProviderConfig", r, r.status == 200, "HTTP %d. Okta and Entra do not need it; other clients read it.", r.status))
	if r.err != nil {
		return out
	}

	r = c.call("GET", "/Users"+filterQ("userName", uname), nil, "conformance: filter with no match")
	add(result("Filter with no match", r, r.status == 200 && num(r.body["totalResults"]) == 0 && hasSchema(r.body, schemaList),
		"HTTP %d, totalResults %v. Want 200, 0 and the ListResponse schema. Entra's connection test sends exactly this.", r.status, r.body["totalResults"]))

	u := User{ID: "conformance", UserName: uname, Email: uname, GivenName: "Mock", FamilyName: "Tester", DisplayName: "Mock Tester", Active: true, Department: "QA"}
	r = c.call("POST", "/Users", c.userResource(u), "conformance: create user")
	id := str(r.body["id"])
	add(result("Create user", r, r.status == 201 && id != "", "HTTP %d, id %q. Want 201 Created with an id.", r.status, id))
	if id == "" {
		return out
	}
	add(result("Create echoes userName", r, str(r.body["userName"]) == uname, "got %q", r.body["userName"]))
	soft(result("Content-Type", r, strings.Contains(r.ctype, "application/scim+json"), "%q. SCIM says application/scim+json.", r.ctype))

	r = c.call("POST", "/Users", c.userResource(u), "conformance: create the same user again")
	add(result("Duplicate userName is 409", r, r.status == 409, "HTTP %d. Want 409 Conflict; otherwise IdP retries create duplicates.", r.status))
	if dup := str(r.body["id"]); okStatus(r.status) && dup != "" && dup != id {
		c.call("DELETE", "/Users/"+dup, nil, "conformance: clean up the duplicate")
	}

	r = c.call("GET", "/Users/"+id, nil, "conformance: get user")
	add(result("Get user by id", r, r.status == 200 && str(r.body["id"]) == id, "HTTP %d", r.status))

	r = c.call("GET", "/Users"+filterQ("userName", uname), nil, "conformance: filter by userName")
	add(result("Filter by userName", r, r.status == 200 && num(r.body["totalResults"]) == 1 && firstResourceID(r.body) == id, "HTTP %d, totalResults %v", r.status, r.body["totalResults"]))

	r = c.call("GET", "/Users"+filterQ("userName", strings.ToUpper(uname)), nil, "conformance: filter, different case")
	soft(result("userName filter ignores case", r, r.status == 200 && num(r.body["totalResults"]) == 1, "totalResults %v. userName is case-insensitive in SCIM (RFC 7643 §4.1.1).", r.body["totalResults"]))

	u.GivenName = "Updated"
	method, body := c.updateBody(u, id)
	r = c.call(method, "/Users/"+id, body, "conformance: update user")
	add(result("Update user ("+method+")", r, okStatus(r.status), "HTTP %d", r.status))
	r = c.call("GET", "/Users/"+id, nil, "conformance: read back the update")
	nm, _ := r.body["name"].(map[string]any)
	add(result("Update persisted", r, str(nm["givenName"]) == "Updated", "name.givenName is %v", nm["givenName"]))

	r = c.call("PATCH", "/Users/"+id, c.deactivateOp(), "conformance: deactivate")
	hint := ""
	if c.flavor.BoolStrings {
		hint = ` This flavor sends "False" as a string, as Entra does. Accept it.`
	}
	add(result("Deactivate (PATCH active)", r, okStatus(r.status), "HTTP %d.%s", r.status, hint))
	r = c.call("GET", "/Users/"+id, nil, "conformance: read back active")
	add(result("Deactivation persisted", r, r.body["active"] == false, "active is %v", r.body["active"]))

	r = c.call("GET", "/Users/"+newUUID(), nil, "conformance: unknown user")
	add(result("Unknown user is 404", r, r.status == 404, "HTTP %d", r.status))
	if r.status == 404 {
		soft(result("404 uses the SCIM Error schema", r, hasSchema(r.body, schemaError), "body: %v", r.body))
	}

	r = c.call("GET", "/Users?startIndex=1&count=1", nil, "conformance: pagination")
	res, _ := r.body["Resources"].([]any)
	add(result("Pagination (count=1)", r, r.status == 200 && len(res) <= 1, "HTTP %d, %d resource(s) returned", r.status, len(res)))

	gname := "mockidp-group-" + randHex(3)
	r = c.call("POST", "/Groups", map[string]any{"schemas": []string{schemaGroup}, "displayName": gname, "members": []any{}}, "conformance: create group")
	gid := str(r.body["id"])
	add(result("Create group", r, r.status == 201 && gid != "", "HTTP %d, id %q", r.status, gid))
	if gid != "" {
		r = c.call("PATCH", "/Groups/"+gid, patchBody(c.op("add", "members", []any{map[string]any{"value": id}})), "conformance: add member")
		add(result("Add member (PATCH)", r, okStatus(r.status), "HTTP %d", r.status))
		r = c.call("GET", "/Groups/"+gid, nil, "conformance: read members")
		add(result("Member persisted", r, slices.Contains(memberIDs(r.body), id), "members: %v", memberIDs(r.body)))
		r = c.call("PATCH", "/Groups/"+gid, patchBody(c.removeMemberOps([]string{id})...), "conformance: remove member")
		add(result("Remove member (PATCH, "+c.flavor.RemoveMember+")", r, okStatus(r.status), "HTTP %d", r.status))
		r = c.call("GET", "/Groups/"+gid, nil, "conformance: read members")
		add(result("Removal persisted", r, !slices.Contains(memberIDs(r.body), id), "members: %v", memberIDs(r.body)))
		r = c.call("DELETE", "/Groups/"+gid, nil, "conformance: delete group")
		add(result("Delete group", r, r.status == 204 || r.status == 200, "HTTP %d", r.status))
	}

	r = c.call("DELETE", "/Users/"+id, nil, "conformance: delete user")
	add(result("Delete user", r, r.status == 204 || r.status == 200, "HTTP %d", r.status))
	r = c.call("GET", "/Users/"+id, nil, "conformance: deleted user is gone")
	add(result("Deleted user is 404", r, r.status == 404, "HTTP %d", r.status))
	return out
}

// autoPush mirrors a change to every target with auto-push on, the way an
// IdP provisions on assignment changes. Callers must not hold store.mu.
func (s *Server) autoPush(tid string, users []User, groups []Group, action string) {
	s.store.mu.Lock()
	var ids []string
	if t := s.store.tenant(tid); t != nil {
		for _, tg := range t.ScimTargets {
			if tg.AutoPush && tg.BaseURL != "" {
				ids = append(ids, tg.ID)
			}
		}
	}
	s.store.mu.Unlock()
	for _, id := range ids {
		go func() {
			c, err := s.newScimClient(tid, id, "")
			if err != nil {
				return
			}
			var cs []check
			for _, u := range users {
				cs = append(cs, c.pushUser(u, action))
			}
			for _, g := range groups {
				cs = append(cs, c.pushGroup(g, action))
			}
			c.finish("auto-push", cs)
		}()
	}
}
