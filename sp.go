package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// The built-in service provider and relying party. They do what a careful
// app should do and show every check, so a simulation's effect is visible
// without writing an app.

type check struct {
	Name   string `json:"name"`
	Result string `json:"result"` // pass | fail | warn
	Detail string `json:"detail,omitempty"`
	Log    int64  `json:"log,omitempty"`
}

type checks []check

func (c *checks) add(name string, ok bool, detail string, a ...any) {
	r := "pass"
	if !ok {
		r = "fail"
	}
	*c = append(*c, check{Name: name, Result: r, Detail: fmt.Sprintf(detail, a...)})
}

func (c *checks) warn(name, detail string, a ...any) {
	*c = append(*c, check{Name: name, Result: "warn", Detail: fmt.Sprintf(detail, a...)})
}

func (c checks) ok() bool {
	for _, x := range c {
		if x.Result == "fail" {
			return false
		}
	}
	return true
}

func (c checks) failures() int {
	n := 0
	for _, x := range c {
		if x.Result == "fail" {
			n++
		}
	}
	return n
}

func (s *Server) registerSP() {
	h := func(pattern string, fn http.HandlerFunc) { s.mux.Handle(pattern, s.traced(fn)) }
	h("GET /sp/saml/{tenant}/{app}/login", s.spSAMLLogin)
	h("POST /sp/saml/{tenant}/{app}/acs", s.spSAMLACS)
	h("GET /sp/oidc/{tenant}/{app}/login", s.spOIDCLogin)
	h("GET /sp/oidc/{tenant}/{app}/callback", s.spOIDCCallback)
	h("POST /sp/oidc/{tenant}/{app}/callback", s.spOIDCCallback)
}

func (s *Server) spSAMLLogin(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "sp.saml"
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t, app := s.samlApp(w, r)
	if t == nil {
		return
	}
	id := samlID()
	put(&s.mem, s.mem.sp, id, &spPending{Tenant: t.ID, App: app.ID, Created: time.Now()})
	sso := s.base + "/t/" + t.ID + "/saml/" + app.ID + "/sso"
	force := ""
	if r.URL.Query().Has("force") {
		force = ` ForceAuthn="true"`
	}
	req := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="%s" xmlns:saml="%s" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" AssertionConsumerServiceURL="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"%s><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy Format="%s" AllowCreate="true"/></samlp:AuthnRequest>`,
		nsProtocol, nsAssertion, id, time.Now().UTC().Format(samlTime), sso, app.ACSURL, force, app.EntityID, app.NameIDFormat)
	e.Summary = "test SP sends AuthnRequest " + id
	e.decode("AuthnRequest", "xml", prettyXML(req))
	http.Redirect(w, r, sso+"?"+url.Values{"SAMLRequest": {deflateB64(req)}, "RelayState": {"mock-idp-test"}}.Encode(), http.StatusFound)
}

type samlExpect struct {
	issuer, audience, acs, tenant, app string
	cert                               *x509.Certificate
}

func validateSig(el *etree.Element, cert *x509.Certificate) error {
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	ctx.IdAttribute = "ID"
	_, err := ctx.Validate(el)
	return err
}

// checkSAMLResponse runs the checks a careful SP runs and returns them with
// the identity it would accept.
func (s *Server) checkSAMLResponse(x string, want samlExpect) (checks, [][2]string) {
	var c checks
	var who [][2]string
	doc := etree.NewDocument()
	if err := doc.ReadFromString(x); err != nil || doc.Root() == nil || doc.Root().Tag != "Response" {
		c.add("Parse", false, "not a SAML Response")
		return c, nil
	}
	resp := doc.Root()
	sc := find(resp, "StatusCode")
	if sc == nil {
		c.add("Status", false, "no StatusCode")
		return c, nil
	}
	if code := sc.SelectAttrValue("Value", ""); !strings.HasSuffix(code, ":Success") {
		detail := code
		if sub := child(sc, "StatusCode"); sub != nil {
			detail += " / " + sub.SelectAttrValue("Value", "")
		}
		c.add("Status", false, "%s %s", detail, text(find(resp, "StatusMessage")))
		return c, nil
	}
	c.add("Status", true, "Success")
	c.add("Response Destination", resp.SelectAttrValue("Destination", "") == want.acs, "got %q, want %q", resp.SelectAttrValue("Destination", ""), want.acs)
	c.add("Response Issuer", text(child(resp, "Issuer")) == want.issuer, "got %q, want %q", text(child(resp, "Issuer")), want.issuer)

	asserts := children(resp, "Assertion")
	if len(asserts) == 0 {
		c.add("Assertion", false, "no Assertion (encrypted assertions are not supported by the test SP)")
		return c, nil
	}
	if len(asserts) > 1 {
		c.add("Exactly one assertion", false, "found %d. This is what a signature-wrapping (XSW) attack looks like. Reject it.", len(asserts))
	}
	as := asserts[0]

	sigs := 0
	if child(resp, "Signature") != nil {
		err := validateSig(resp, want.cert)
		c.add("Response signature", err == nil, "%s", errOr(err, "valid, signed with the metadata certificate"))
		if err == nil {
			sigs++
		}
	}
	if child(as, "Signature") != nil {
		err := validateSig(as, want.cert)
		c.add("Assertion signature", err == nil, "%s", errOr(err, "valid, signed with the metadata certificate"))
		if err == nil {
			sigs++
		}
	} else if len(asserts) > 1 {
		c.add("Assertion signature", false, "the first assertion is unsigned. An SP that reads it would sign in %s", text(find(as, "NameID")))
	}
	if child(resp, "Signature") == nil && child(as, "Signature") == nil {
		c.add("Signed", false, "nothing is signed. Anyone could forge this response.")
	} else if sigs == 0 {
		c.add("Signed", false, "no signature verified")
	}
	if m := find(resp, "SignatureMethod"); m != nil && strings.Contains(m.SelectAttrValue("Algorithm", ""), "sha1") {
		c.warn("Signature algorithm", "rsa-sha1. Weak; many SPs reject it.")
	}

	c.add("Assertion Issuer", text(child(as, "Issuer")) == want.issuer, "got %q, want %q", text(child(as, "Issuer")), want.issuer)
	aud := text(find(as, "Audience"))
	c.add("Audience", aud == want.audience, "got %q, want %q (the SP entity ID)", aud, want.audience)
	scd := find(as, "SubjectConfirmationData")
	if scd != nil {
		c.add("Recipient", scd.SelectAttrValue("Recipient", "") == want.acs, "got %q, want %q", scd.SelectAttrValue("Recipient", ""), want.acs)
	}

	irt := resp.SelectAttrValue("InResponseTo", "")
	if irt == "" {
		c.warn("InResponseTo", "missing: an IdP-initiated (unsolicited) response. Accept only if the SP allows it.")
	} else if p := take(&s.mem, s.mem.sp, irt); p != nil && p.Tenant == want.tenant && p.App == want.app {
		c.add("InResponseTo", true, "matches AuthnRequest %s sent %s ago (now used, so a replay fails)", irt, time.Since(p.Created).Round(time.Second))
	} else {
		c.add("InResponseTo", false, "%s matches no AuthnRequest this SP sent, or it was already used (replay)", irt)
	}

	now, leeway := time.Now().UTC(), 60*time.Second
	if cond := find(as, "Conditions"); cond != nil {
		if nb, err := time.Parse(time.RFC3339, cond.SelectAttrValue("NotBefore", "")); err == nil {
			c.add("NotBefore", !now.Add(leeway).Before(nb), "%s; now %s (60 s leeway)", nb.Format(time.RFC3339), now.Format(time.RFC3339))
		}
		if na, err := time.Parse(time.RFC3339, cond.SelectAttrValue("NotOnOrAfter", "")); err == nil {
			c.add("NotOnOrAfter", now.Add(-leeway).Before(na), "%s; now %s (60 s leeway)", na.Format(time.RFC3339), now.Format(time.RFC3339))
		}
	}

	nid := find(as, "NameID")
	if nid == nil {
		c.add("NameID", false, "missing")
	} else {
		first, full := "", ""
		hasComment := false
		for _, tok := range nid.Child {
			switch v := tok.(type) {
			case *etree.CharData:
				if first == "" {
					first = v.Data
				}
				full += v.Data
			case *etree.Comment:
				hasComment = true
			}
		}
		if hasComment {
			c.add("NameID", false, "contains an XML comment. Full value %q, but a parser reading the first text node sees %q (CVE-2017-11427 class)", full, first)
		} else {
			c.add("NameID", true, "%s", full)
		}
		who = append(who, [2]string{"NameID", full}, [2]string{"Format", nid.SelectAttrValue("Format", "")})
	}
	if stmt := find(as, "AttributeStatement"); stmt != nil {
		for _, a := range children(stmt, "Attribute") {
			var vals []string
			for _, v := range children(a, "AttributeValue") {
				vals = append(vals, v.Text())
			}
			who = append(who, [2]string{a.SelectAttrValue("Name", ""), strings.Join(vals, ", ")})
		}
	}
	return c, who
}

func errOr(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}

func (s *Server) spSAMLACS(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "sp.saml"
	r.ParseForm()
	s.store.mu.Lock()
	t, app := s.samlApp(w, r)
	if t == nil {
		s.store.mu.Unlock()
		return
	}
	want := samlExpect{issuer: s.samlIssuer(t, app), audience: app.EntityID, acs: app.ACSURL, tenant: t.ID, app: app.ID, cert: t.cert}
	s.store.mu.Unlock()

	x, err := decodeSAMLMessage(r.Form.Get("SAMLResponse"))
	if err != nil || x == "" {
		s.errorPage(w, r, t, 400, "No SAMLResponse", "POST a SAMLResponse form field.")
		return
	}
	pretty := prettyXML(x)
	e.decode("SAMLResponse", "xml", pretty)
	c, who := s.checkSAMLResponse(x, want)
	e.decode("SP checks", "json", c)
	e.Summary = fmt.Sprintf("test SP checked a SAMLResponse: %d failed", c.failures())
	if !c.ok() {
		e.Level = "error"
	}
	title := "Signed in"
	if !c.ok() {
		title = fmt.Sprintf("Rejected: %d check(s) failed", c.failures())
	}
	base := "/sp/saml/" + t.ID + "/" + app.ID
	s.page(w, 200, "result", t, pageData{Title: title, OK: c.ok(), Wide: true, Provider: "Test SP · " + providers[t.Provider].Name,
		Info: "The built-in SAML service provider checked the response the way a careful app should.", Checks: c, Claims: who,
		Raw:   []rawBlock{{"SAMLResponse", pretty}},
		Links: [][2]string{{"Sign in again", base + "/login"}, {"Sign in as someone else", base + "/login?force=1"}, {"Simulations", "/#/t/" + t.ID + "/simulations"}, {"Logs", "/#/logs"}}})
}

func (s *Server) spOIDCLogin(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "sp.oidc"
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, false)
	if t == nil {
		return
	}
	app := t.app(r.PathValue("app"))
	if app == nil || app.Type != "oidc" {
		s.errorPage(w, r, t, 404, "Unknown OIDC app", r.PathValue("app"))
		return
	}
	cb := s.base + "/sp/oidc/" + t.ID + "/" + app.ID + "/callback"
	if !slices.Contains(app.RedirectURIs, cb) {
		s.errorPage(w, r, t, 400, "Test app not registered", "Add "+cb+" to the app's redirect URIs to use the built-in test app.")
		return
	}
	state, nonce, verifier := randHex(12), randHex(12), randHex(32)
	sum := sha256.Sum256([]byte(verifier))
	put(&s.mem, s.mem.sp, state, &spPending{Tenant: t.ID, App: app.ID, Nonce: nonce, Verifier: verifier, Created: time.Now()})
	q := url.Values{"client_id": {app.ClientID}, "redirect_uri": {cb}, "response_type": {"code"},
		"scope": {"openid profile email offline_access"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {b64(sum[:])}, "code_challenge_method": {"S256"}}
	if p := r.URL.Query().Get("prompt"); p != "" {
		q.Set("prompt", p)
	}
	e.Summary = "test app starts code flow with PKCE"
	http.Redirect(w, r, s.issuer(t.ID)+"/authorize?"+q.Encode(), http.StatusFound)
}

func (s *Server) spOIDCCallback(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "sp.oidc"
	r.ParseForm()
	s.store.mu.Lock()
	t := s.lookup(w, r, false)
	var app *App
	if t != nil {
		if app = t.app(r.PathValue("app")); app == nil {
			s.errorPage(w, r, t, 404, "Unknown OIDC app", r.PathValue("app"))
		}
	}
	if t == nil || app == nil {
		s.store.mu.Unlock()
		return
	}
	cid, secret, public, iss := app.ClientID, app.ClientSecret, app.Public, s.issuer(t.ID)
	pub, prov := &t.key.PublicKey, providers[t.Provider]
	s.store.mu.Unlock()

	base := "/sp/oidc/" + t.ID + "/" + app.ID
	d := pageData{Title: "Signed in", Wide: true, Provider: "Test app · " + prov.Name,
		Info:  "The built-in OIDC app ran the code flow with PKCE and checked the tokens the way a careful app should.",
		Links: [][2]string{{"Sign in again", base + "/login"}, {"Sign in as someone else", base + "/login?prompt=login"}, {"Simulations", "/#/t/" + t.ID + "/simulations"}, {"Logs", "/#/logs"}}}
	var c checks
	show := func() {
		d.Checks, d.OK = c, c.ok()
		if !d.OK {
			d.Title = fmt.Sprintf("Rejected: %d check(s) failed", c.failures())
			e.Level = "error"
		}
		e.decode("app checks", "json", c)
		e.Summary = fmt.Sprintf("test app checked the sign-in: %d failed", c.failures())
		s.page(w, 200, "result", t, d)
	}

	if er := r.Form.Get("error"); er != "" {
		c.add("Authorization response", false, "the IdP returned error=%s: %s", er, r.Form.Get("error_description"))
		show()
		return
	}
	p := take(&s.mem, s.mem.sp, r.Form.Get("state"))
	c.add("state", p != nil && p.App == app.ID, "%s", map[bool]string{true: "matches the one this app sent (CSRF check)", false: "matches nothing this app sent. A CSRF attempt looks like this."}[p != nil])
	if p == nil {
		show()
		return
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {r.Form.Get("code")}, "redirect_uri": {s.base + base + "/callback"}, "code_verifier": {p.Verifier}}
	if public {
		form.Set("client_id", cid)
	}
	req := httptest.NewRequest("POST", "/t/"+t.ID+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !public {
		req.SetBasicAuth(url.QueryEscape(cid), url.QueryEscape(secret))
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var tok map[string]any
	json.Unmarshal(rec.Body.Bytes(), &tok)
	c.add("Token exchange", rec.Code == 200, "HTTP %d %s", rec.Code, map[bool]string{true: "", false: rec.Body.String()}[rec.Code == 200])
	if rec.Code != 200 {
		show()
		return
	}
	d.Raw = append(d.Raw, rawBlock{"Token response", prettyJSON(tok)})
	idt := str(tok["id_token"])
	if idt == "" {
		c.add("ID token", false, "none in the token response")
		show()
		return
	}
	claims := checkIDToken(&c, idt, pub, iss, cid, p.Nonce, str(tok["access_token"]))
	h, _, _ := decodeJWT(idt)
	d.Raw = append(d.Raw, rawBlock{"ID token (decoded)", prettyJSON(map[string]any{"header": h, "claims": claims, "times": jwtTimes(claims)})})
	for _, k := range []string{"sub", "email", "email_verified", "name", "preferred_username", "oid", "tid", "hd", "groups"} {
		if v, ok := claims[k]; ok {
			d.Claims = append(d.Claims, [2]string{k, fmt.Sprint(v)})
		}
	}

	ui := httptest.NewRequest("GET", "/t/"+t.ID+"/userinfo", nil)
	ui.Header.Set("Authorization", "Bearer "+str(tok["access_token"]))
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, ui)
	c.add("userinfo", rec.Code == 200, "HTTP %d", rec.Code)
	d.Raw = append(d.Raw, rawBlock{"userinfo", rec.Body.String()})
	show()
}

// checkIDToken runs the ID token checks from OIDC Core 3.1.3.7.
func checkIDToken(c *checks, idt string, pub *rsa.PublicKey, iss, aud, nonce, access string) map[string]any {
	h, cl, err := decodeJWT(idt)
	if err != nil {
		c.add("ID token format", false, "%v", err)
		return nil
	}
	alg := str(h["alg"])
	c.add("alg", alg == "RS256", "%s%s", alg, map[bool]string{true: "", false: ". Never accept alg=none or an algorithm you did not expect."}[alg == "RS256"])
	if alg == "RS256" {
		c.add("kid", str(h["kid"]) == kid(pub), "%s %s", str(h["kid"]), map[bool]string{true: "is in the JWKS", false: "is not in the JWKS. Refetch the JWKS once, then reject."}[str(h["kid"]) == kid(pub)])
		err := verifyJWT(idt, pub)
		c.add("Signature", err == nil, "%s", errOr(err, "valid"))
	}
	c.add("iss", str(cl["iss"]) == iss, "got %q, want %q", cl["iss"], iss)
	audOK := str(cl["aud"]) == aud
	if list, ok := cl["aud"].([]any); ok {
		audOK = slices.ContainsFunc(list, func(v any) bool { return str(v) == aud })
	}
	c.add("aud", audOK, "got %v, want %q", cl["aud"], aud)
	now := time.Now().Unix()
	c.add("exp", num(cl["exp"]) > now-60, "%s", jwtTimes(cl)["exp"])
	c.add("iat", num(cl["iat"]) <= now+60, "%s", jwtTimes(cl)["iat"])
	c.add("nonce", str(cl["nonce"]) == nonce, "got %q, want %q", cl["nonce"], nonce)
	if ah := str(cl["at_hash"]); ah != "" {
		c.add("at_hash", ah == atHash(access), "%s", map[bool]string{true: "matches the access token", false: "does not match the access token"}[ah == atHash(access)])
	}
	switch v, ok := cl["email_verified"]; {
	case cl["email"] == nil:
		c.warn("email", "no email claim. Key users on sub (or oid + tid for Entra), never on email.")
	case !ok:
		c.warn("email_verified", "not sent (Entra never sends it). Do not trust this email for account linking.")
	case v != true:
		c.warn("email_verified", "false. Do not link accounts on this email.")
	}
	return cl
}
