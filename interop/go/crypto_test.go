package interop

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
)

func spKeypair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "crewjam-sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return k, c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// cryptoSP is a crewjam SP that signs its requests and decrypts assertions,
// registered in a fresh tenant with encryption and signed requests required.
func cryptoSP(t *testing.T, alg, kt string) (*saml.ServiceProvider, tenant) {
	key, cert, certPEM := spKeypair(t)
	ten := newTenant(t, "entra")
	sims(t, ten.ID, nil)
	const entity, acs = "urn:crypto:crewjam", "https://sp.example/acs"
	api(t, "POST", "/tenants/"+ten.ID+"/apps", map[string]any{"type": "saml", "name": "crewjam-crypto", "entityId": entity, "acsUrl": acs,
		"encryptAssertion": true, "encryptionAlg": alg, "keyTransportAlg": kt, "spEncryptionCert": certPEM,
		"spSigningCert": certPEM, "requireSignedRequests": true}, nil)
	var ep endpoints
	api(t, "GET", "/tenants/"+ten.ID+"/endpoints", nil, &ep)
	var mdURL *url.URL
	for _, a := range ep.Apps {
		if a.SpEntityID == entity {
			mdURL, _ = url.Parse(a.MetadataURL)
		}
	}
	md, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *mdURL)
	if err != nil {
		t.Fatal(err)
	}
	acsURL, _ := url.Parse(acs)
	return &saml.ServiceProvider{EntityID: entity, AcsURL: *acsURL, IDPMetadata: md,
		Key: key, Certificate: cert, SignatureMethod: dsig.RSASHA256SignatureMethod}, ten
}

func TestCrewjamDecryptsEveryAlgorithm(t *testing.T) {
	for _, alg := range []string{"aes128-cbc", "aes256-cbc", "aes128-gcm", "aes256-gcm"} {
		for _, kt := range []string{"rsa-oaep", "rsa-1_5"} {
			t.Run(alg+"+"+kt, func(t *testing.T) {
				sp, ten := cryptoSP(t, alg, kt)
				a, err := samlLogin(sp) // HTTP-Redirect, signed by crewjam
				record("crewjam/saml", "decrypt "+alg+" + "+kt, err)
				if err != nil {
					// The IdP refusing is our bug. crewjam 0.5 does not implement
					// AES-256-GCM, a library gap that is recorded, not failed.
					if strings.Contains(err.Error(), "IdP sent no") || !strings.Contains(err.Error(), "not implemented") {
						t.Fatal(err)
					}
					return
				}
				if a.Subject.NameID.Value != alice(ten.ID) {
					t.Errorf("NameID %s", a.Subject.NameID.Value)
				}
			})
		}
	}
}

func TestCrewjamSignedPostRequest(t *testing.T) {
	sp, _ := cryptoSP(t, "aes256-cbc", "rsa-oaep")
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPPostBinding), saml.HTTPPostBinding, saml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	for _, m := range postField.FindAllStringSubmatch(string(req.Post("rs")), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	resp, err := noRedirect.PostForm(sp.GetSSOBindingLocation(saml.HTTPPostBinding), form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP refused crewjam's signed POST request: HTTP %d %s", resp.StatusCode, body)
	}
	if _, err := postSAMLResponse(sp, body, []string{req.ID}); err != nil {
		t.Fatal(err)
	}
}

func TestCrewjamUntrustedSignerRefused(t *testing.T) {
	sp, _ := cryptoSP(t, "aes256-cbc", "rsa-oaep")
	other, _, _ := spKeypair(t)
	sp.Key = other // signs with a key the app does not trust
	_, err := samlLogin(sp)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Errorf("request signed by an untrusted key: %v", err)
	}
}
