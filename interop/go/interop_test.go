// Interop tests: real Go libraries (crewjam/saml, coreos/go-oidc) against a
// running mock-idp. Run through ../run.sh, or set MOCKIDP_URL.
package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/oauth2"
)

var base = func() string {
	if u := os.Getenv("MOCKIDP_URL"); u != "" {
		return u
	}
	return "http://localhost:7171"
}()

var tenants = map[string]string{
	"okta": "acme.example", "entra": "contoso.example", "google": "globex.example", "onelogin": "initech.example",
	"pingone": "umbrella.example", "jumpcloud": "hooli.example", "adfs": "wayne.example", "auth0": "stark.example", "keycloak": "cyberdyne.example",
}

func alice(t string) string { return "alice@" + tenants[t] }

func api(t *testing.T, method, path string, body any, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, base+"/api"+path, bytes.NewReader(b))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("%s %s: %s", method, path, raw)
	}
	if out != nil {
		json.Unmarshal(raw, out)
	}
}

func sims(t *testing.T, tenant string, s map[string]any) {
	api(t, "DELETE", "/tenants/"+tenant+"/simulations", nil, nil)
	m := map[string]any{"autoLogin": alice(tenant)}
	for k, v := range s {
		m[k] = v
	}
	api(t, "PATCH", "/tenants/"+tenant+"/simulations", m, nil)
}

// matrix records what each library did with each fault, printed at the end.
var matrix = map[string]map[string]string{}

func record(lib, sim string, err error) {
	if matrix[sim] == nil {
		matrix[sim] = map[string]string{}
	}
	out := "ACCEPTED"
	if err != nil {
		out = "rejected: " + err.Error()
	}
	if len(out) > 90 {
		out = out[:90]
	}
	matrix[sim][lib] = out
}

func TestMain(m *testing.M) {
	code := m.Run()
	var keys []string
	for k := range matrix {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("\nFault matrix (rejected = the library caught it)")
	for _, k := range keys {
		for lib, o := range matrix[k] {
			fmt.Printf("  %-24s %-12s %s\n", k, lib, o)
		}
	}
	os.Exit(code)
}

func simValue(sim string) (string, any) {
	k, v, ok := strings.Cut(sim, ":")
	if !ok {
		return k, true
	}
	var n int
	if _, err := fmt.Sscan(v, &n); err == nil {
		return k, n
	}
	return k, v
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// ---------- SAML: crewjam/saml ----------

type endpoints struct {
	CertificatePem string `json:"certificatePem"`
	Apps           []struct {
		ID, Type, MetadataURL, SpEntityID, AcsURL, IdpEntityID string
	} `json:"apps"`
}

func samlSP(t *testing.T, tenant string) *saml.ServiceProvider {
	t.Helper()
	const entity, acs = "urn:interop:crewjam", "https://sp.example/saml/acs"
	var ep endpoints
	api(t, "GET", "/tenants/"+tenant+"/endpoints", nil, &ep)
	found := false
	for _, a := range ep.Apps {
		found = found || a.SpEntityID == entity
	}
	if !found {
		api(t, "POST", "/tenants/"+tenant+"/apps", map[string]any{"type": "saml", "name": "crewjam", "entityId": entity, "acsUrl": acs}, nil)
		api(t, "GET", "/tenants/"+tenant+"/endpoints", nil, &ep)
	}
	for _, a := range ep.Apps {
		if a.SpEntityID == entity {
			mdURL, _ := url.Parse(a.MetadataURL)
			md, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *mdURL)
			if err != nil {
				t.Fatal(err)
			}
			acsURL, _ := url.Parse(acs)
			return &saml.ServiceProvider{EntityID: entity, AcsURL: *acsURL, IDPMetadata: md}
		}
	}
	t.Fatal("app not created")
	return nil
}

var samlResponseField = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

func samlLogin(sp *saml.ServiceProvider) (*saml.Assertion, error) {
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	u, err := req.Redirect("relay", sp)
	if err != nil {
		return nil, err
	}
	resp, err := noRedirect.Get(u.String())
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := samlResponseField.FindSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("IdP sent no SAMLResponse (HTTP %d)", resp.StatusCode)
	}
	form := url.Values{"SAMLResponse": {html.UnescapeString(string(m[1]))}}
	post := httptest.NewRequest("POST", sp.AcsURL.String(), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.ParseForm()
	a, err := sp.ParseResponse(post, []string{req.ID})
	var ire *saml.InvalidResponseError
	if errors.As(err, &ire) {
		return nil, ire.PrivateErr // the reason; the public error is deliberately vague
	}
	return a, err
}

func attr(a *saml.Assertion, name string) []string {
	var out []string
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			if at.Name == name {
				for _, v := range at.Values {
					out = append(out, v.Value)
				}
			}
		}
	}
	return out
}

func TestCrewjamSAMLEveryProvider(t *testing.T) {
	for tenant := range tenants {
		t.Run(tenant, func(t *testing.T) {
			sims(t, tenant, nil)
			a, err := samlLogin(samlSP(t, tenant))
			if err != nil {
				t.Fatal(err)
			}
			if a.Subject == nil || a.Subject.NameID == nil || a.Subject.NameID.Value == "" {
				t.Fatal("no NameID")
			}
		})
	}
	sims(t, "entra", nil)
	a, err := samlLogin(samlSP(t, "entra"))
	if err != nil {
		t.Fatal(err)
	}
	if got := attr(a, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"); len(got) != 1 || got[0] != alice("entra") {
		t.Errorf("Entra email attribute: %v", got)
	}
	if got := attr(a, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"); len(got) != 3 {
		t.Errorf("Entra groups (object ids): %v", got)
	}
}

func TestCrewjamSAMLFaults(t *testing.T) {
	mustReject := []string{"samlExpired", "samlNotYetValid", "samlBadSignature", "samlWrongCert", "samlUnsigned", "samlWrongAudience",
		"samlWrongIssuer", "samlWrongInResponseTo", "samlSignatureWrapping", "samlWrongDestination", "samlWrongRecipient", "authError:access_denied"}
	info := []string{"samlSha1", "samlMissingNameId", "samlNoAttributes", "samlCommentInjection", "clockSkewSec:300"}
	sp := samlSP(t, "okta")
	sims(t, "okta", nil)
	if _, err := samlLogin(sp); err != nil {
		t.Fatalf("a normal sign-in must work before faults mean anything: %v", err)
	}
	for i, sim := range append(mustReject, info...) {
		t.Run(sim, func(t *testing.T) {
			k, v := simValue(sim)
			sims(t, "okta", map[string]any{k: v})
			a, err := samlLogin(sp)
			record("crewjam/saml", sim, err)
			if i < len(mustReject) && err == nil {
				t.Errorf("%s was accepted", sim)
			}
			if k == "samlCommentInjection" && err == nil && a.Subject.NameID.Value == alice("okta") {
				t.Errorf("comment injection truncated the NameID to %s", a.Subject.NameID.Value)
			}
		})
	}
	sims(t, "okta", nil)
}

// ---------- OIDC: coreos/go-oidc + x/oauth2 ----------

const redirect = "https://rp.example/callback"

type rpClient struct {
	provider *oidc.Provider
	cfg      oauth2.Config
}

func newRP(t *testing.T, tenant string) *rpClient {
	t.Helper()
	var ten struct {
		Apps []struct{ Name, ClientID, ClientSecret string }
	}
	api(t, "GET", "/tenants/"+tenant, nil, &ten)
	var app struct{ ClientID, ClientSecret string }
	for _, a := range ten.Apps {
		if a.Name == "go-oidc" {
			app.ClientID, app.ClientSecret = a.ClientID, a.ClientSecret
		}
	}
	if app.ClientID == "" {
		api(t, "POST", "/tenants/"+tenant+"/apps", map[string]any{"type": "oidc", "name": "go-oidc", "redirectUris": []string{redirect}}, &app)
	}
	p, err := oidc.NewProvider(context.Background(), base+"/t/"+tenant)
	if err != nil {
		t.Fatal(err)
	}
	return &rpClient{p, oauth2.Config{ClientID: app.ClientID, ClientSecret: app.ClientSecret, Endpoint: p.Endpoint(), RedirectURL: redirect,
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess}}}
}

// login runs code + PKCE and does every check go-oidc's docs ask the app to do.
func (rp *rpClient) login() (*oidc.IDToken, *oauth2.Token, error) {
	ctx := context.Background()
	state, nonce, verifier := "st-"+oauth2.GenerateVerifier()[:8], "n-"+oauth2.GenerateVerifier()[:8], oauth2.GenerateVerifier()
	resp, err := noRedirect.Get(rp.cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
	if err != nil {
		return nil, nil, err
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || err != nil || !strings.HasPrefix(loc.String(), redirect) {
		return nil, nil, fmt.Errorf("authorize answered HTTP %d", resp.StatusCode)
	}
	q := loc.Query()
	if e := q.Get("error"); e != "" {
		return nil, nil, fmt.Errorf("authorization error %s", e)
	}
	if q.Get("state") != state {
		return nil, nil, errors.New("state mismatch")
	}
	tok, err := rp.cfg.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, err
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	if idt.Nonce != nonce {
		return nil, nil, errors.New("nonce mismatch")
	}
	if idt.AccessTokenHash != "" {
		if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
			return nil, nil, err
		}
	}
	return idt, tok, nil
}

func TestGoOIDCEveryProvider(t *testing.T) {
	for tenant := range tenants {
		t.Run(tenant, func(t *testing.T) {
			sims(t, tenant, nil)
			rp := newRP(t, tenant)
			idt, tok, err := rp.login()
			if err != nil {
				t.Fatal(err)
			}
			ui, err := rp.provider.UserInfo(context.Background(), oauth2.StaticTokenSource(tok))
			if err != nil {
				t.Fatal(err)
			}
			if ui.Subject != idt.Subject {
				t.Errorf("userinfo sub %s != id token sub %s", ui.Subject, idt.Subject)
			}
			// x/oauth2 refreshes when the token is expired
			tok.Expiry = tok.Expiry.Add(-2 * 3600e9)
			if _, err := rp.cfg.TokenSource(context.Background(), tok).Token(); err != nil {
				t.Errorf("refresh: %v", err)
			}
		})
	}
}

func TestGoOIDCFaults(t *testing.T) {
	mustReject := []string{"oidcExpired", "oidcWrongIssuer", "oidcWrongAudience", "oidcWrongNonce", "oidcWrongState", "oidcAlgNone",
		"oidcBadSignature", "oidcUnknownKid", "oidcWrongAtHash", "authError:access_denied", "tokenError:invalid_grant", "httpStatus:503"}
	info := []string{"oidcMissingEmail", "oidcEmailUnverified", "clockSkewSec:300"}
	sims(t, "okta", nil)
	rp := newRP(t, "okta")
	if _, _, err := rp.login(); err != nil {
		t.Fatalf("a normal sign-in must work before faults mean anything: %v", err)
	}
	for i, sim := range append(mustReject, info...) {
		t.Run(sim, func(t *testing.T) {
			k, v := simValue(sim)
			sims(t, "okta", map[string]any{k: v})
			_, _, err := rp.login()
			record("go-oidc", sim, err)
			if i < len(mustReject) && err == nil {
				t.Errorf("%s was accepted", sim)
			}
		})
	}
	sims(t, "okta", nil)
}

// Entra signs only the assertion, so a forged assertion beside it breaks no
// signature. This is the case signature wrapping attacks target.
func TestCrewjamSAMLWrappingAssertionOnlySigned(t *testing.T) {
	sp := samlSP(t, "entra")
	sims(t, "entra", map[string]any{"samlSignatureWrapping": true})
	defer sims(t, "entra", nil)
	a, err := samlLogin(sp)
	if err == nil {
		err = fmt.Errorf("kept the signed assertion, ignored the forged one: %s", a.Subject.NameID.Value)
		if a.Subject.NameID.Value == "attacker@evil.example" {
			t.Errorf("signed in as the attacker")
		}
	}
	record("crewjam/saml", "samlSignatureWrapping (assertion-only signing)", err)
}
