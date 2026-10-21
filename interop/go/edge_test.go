package interop

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"golang.org/x/oauth2"
)

type tenant struct {
	ID     string
	Domain string
	Users  []struct{ ID, UserName string }
}

// newTenant makes an isolated tenant so a test's faults and key rotations
// touch nothing else.
func newTenant(t *testing.T, provider string) tenant {
	t.Helper()
	var ten tenant
	api(t, "POST", "/tenants", map[string]any{"name": "go edge " + provider + " " + oauth2.GenerateVerifier()[:5], "provider": provider}, &ten)
	tenants[ten.ID] = ten.Domain // lets sims() autoLogin alice in this tenant
	t.Cleanup(func() {
		delete(tenants, ten.ID)
		api(t, "DELETE", "/tenants/"+ten.ID, nil, nil)
	})
	return ten
}

func postSAMLResponse(sp *saml.ServiceProvider, page []byte, ids []string) (*saml.Assertion, error) {
	m := samlResponseField.FindSubmatch(page)
	if m == nil {
		return nil, io.ErrUnexpectedEOF
	}
	form := url.Values{"SAMLResponse": {html.UnescapeString(string(m[1]))}}
	post := httptest.NewRequest("POST", sp.AcsURL.String(), strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.ParseForm()
	return sp.ParseResponse(post, ids)
}

func TestCrewjamIdPInitiated(t *testing.T) {
	ten := newTenant(t, "okta")
	sims(t, ten.ID, nil)
	sp := samlSP(t, ten.ID)
	initURL := strings.Replace(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), "/sso", "/init", 1)
	get := func() []byte {
		resp, err := noRedirect.Get(initURL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	if _, err := postSAMLResponse(sp, get(), nil); err == nil {
		t.Error("an SP without AllowIDPInitiated accepted an unsolicited response")
	}
	sp.AllowIDPInitiated = true
	a, err := postSAMLResponse(sp, get(), nil)
	if err != nil {
		t.Fatalf("AllowIDPInitiated SP refused: %v", err)
	}
	if a.Subject.NameID.Value != alice(ten.ID) {
		t.Errorf("NameID %s", a.Subject.NameID.Value)
	}
}

var postField = regexp.MustCompile(`name="(SAMLRequest|RelayState)" value="([^"]*)"`)

// The AuthnRequest arrives by HTTP-POST instead of Redirect: no DEFLATE.
func TestCrewjamPostBindingRequest(t *testing.T) {
	ten := newTenant(t, "entra")
	sims(t, ten.ID, nil)
	sp := samlSP(t, ten.ID)
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPPostBinding), saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	for _, m := range postField.FindAllStringSubmatch(string(req.Post("rs-1")), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	resp, err := noRedirect.PostForm(sp.GetSSOBindingLocation(saml.HTTPPostBinding), form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `name="RelayState" value="rs-1"`) {
		t.Error("RelayState lost")
	}
	if _, err := postSAMLResponse(sp, body, []string{req.ID}); err != nil {
		t.Fatal(err)
	}
}

// go-oidc's RemoteKeySet refetches the JWKS when it sees an unknown kid, so a
// long-lived verifier keeps working across a rotation.
func TestGoOIDCAcrossKeyRotation(t *testing.T) {
	ten := newTenant(t, "okta")
	sims(t, ten.ID, nil)
	rp := newRP(t, ten.ID)
	if _, _, err := rp.login(); err != nil {
		t.Fatal(err)
	}
	api(t, "POST", "/tenants/"+ten.ID+"/rotate-keys", nil, nil)
	_, _, err := rp.login()
	record("go-oidc", "key rotation (same verifier)", err)
	if err != nil {
		t.Errorf("after rotation: %v", err)
	}
}

func TestGoOIDCUserInfoRejectsForgedToken(t *testing.T) {
	ten := newTenant(t, "okta")
	sims(t, ten.ID, nil)
	rp := newRP(t, ten.ID)
	_, tok, err := rp.login()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok.AccessToken, ".")
	forged := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	_, err = rp.provider.UserInfo(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: forged, TokenType: "Bearer"}))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("forged access token: %v", err)
	}
	resp, _ := http.Get(base + "/t/" + ten.ID + "/userinfo")
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("no token: HTTP %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}
