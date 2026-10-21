package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsStatus    = "urn:oasis:names:tc:SAML:2.0:status:"
	samlTime    = "2006-01-02T15:04:05.000Z"
)

func samlID() string { return "_" + randHex(16) }

func (s *Server) samlApp(w http.ResponseWriter, r *http.Request) (*Tenant, *App) {
	t := s.lookup(w, r, false)
	if t == nil {
		return nil, nil
	}
	app := t.app(r.PathValue("app"))
	if app == nil || app.Type != "saml" {
		s.errorPage(w, r, t, 404, "Unknown SAML app", "There is no SAML app "+r.PathValue("app")+" in "+t.Name+".")
		return nil, nil
	}
	return t, app
}

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	entry(r).Kind = "saml.metadata"
	if s.network(w, r) {
		return
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t, app := s.samlApp(w, r)
	if t == nil {
		return
	}
	base := s.base + "/t/" + t.ID + "/saml/" + app.ID
	e := html.EscapeString
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	if r.URL.Query().Has("download") {
		w.Header().Set("Content-Disposition", `attachment; filename="`+t.ID+"-"+app.ID+`-metadata.xml"`)
	}
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/slo"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/slo"/>
    <md:NameIDFormat>%s</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`, e(s.samlIssuer(t, app)), base64.StdEncoding.EncodeToString(t.cert.Raw), base, base, e(app.NameIDFormat), base, base)
}

// samlSSO receives an AuthnRequest (Redirect or POST binding) or, with no
// request, starts an IdP-initiated sign-in.
func (s *Server) samlSSO(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "saml.sso"
	if s.network(w, r) {
		return
	}
	r.ParseForm()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t, app := s.samlApp(w, r)
	if t == nil {
		return
	}
	in := &interaction{Kind: "saml", Tenant: t.ID, App: app.ID, RelayState: r.Form.Get("RelayState")}
	if raw := r.Form.Get("SAMLRequest"); raw != "" {
		x, err := decodeSAMLMessage(raw)
		if err != nil {
			s.errorPage(w, r, t, 400, "Bad SAMLRequest", "Could not decode it: "+err.Error())
			return
		}
		e.decode("SAMLRequest", "xml", prettyXML(x))
		doc := etree.NewDocument()
		if err := doc.ReadFromString(x); err != nil || doc.Root() == nil || doc.Root().Tag != "AuthnRequest" {
			s.errorPage(w, r, t, 400, "Bad SAMLRequest", "It is not an AuthnRequest.")
			return
		}
		req := doc.Root()
		in.RequestID = req.SelectAttrValue("ID", "")
		in.ForceAuthn = req.SelectAttrValue("ForceAuthn", "") == "true"
		in.Passive = req.SelectAttrValue("IsPassive", "") == "true"
		iss := text(child(req, "Issuer"))
		e.Summary = "SAML AuthnRequest from " + iss
		if iss != app.EntityID {
			s.errorPage(w, r, t, 400, "Unknown service provider", fmt.Sprintf("The AuthnRequest Issuer is %q but this app's entity ID is %q. Okta and Entra stop here with a similar error.", iss, app.EntityID))
			return
		}
		if acs := req.SelectAttrValue("AssertionConsumerServiceURL", ""); acs != "" && acs != app.ACSURL {
			e.warn("AuthnRequest asks for ACS %s but the app is set to %s. Using the configured ACS, as Okta and Entra do.", acs, app.ACSURL)
		}
		if find(req, "Signature") == nil && r.Form.Get("Signature") == "" {
			e.note("AuthnRequest is unsigned (accepted; this IdP does not require signed requests)")
		}
	} else {
		e.Summary = "SAML IdP-initiated sign-in to " + app.Name
		if in.RelayState == "" {
			in.RelayState = app.RelayState
		}
	}
	if code := t.Sims.AuthError; code != "" {
		s.fail(w, r, t, in, code, "simulated by mock-idp")
		s.consumeOnce(t)
		return
	}
	s.beginLogin(w, r, t, in)
}

func (s *Server) samlComplete(w http.ResponseWriter, r *http.Request, t *Tenant, app *App, in *interaction, u *User, errCode string) {
	x, err := s.samlResponse(t, app, u, in.RequestID, errCode, entry(r))
	if err != nil {
		s.errorPage(w, r, t, 500, "Could not sign the response", err.Error())
		return
	}
	s.postToSP(w, r, t, app.ACSURL, "SAMLResponse", x, in.RelayState)
}

func (s *Server) postToSP(w http.ResponseWriter, r *http.Request, t *Tenant, target, param, x, relay string) {
	pretty := prettyXML(x)
	entry(r).decode(param, "xml", pretty)
	fields := [][2]string{{param, base64.StdEncoding.EncodeToString([]byte(x))}}
	if relay != "" {
		fields = append(fields, [2]string{"RelayState", relay})
	}
	if t.Sims.PauseBeforeSend {
		s.page(w, 200, "pause", t, pageData{Title: "Paused", Wide: true, Target: target, Method: "POST", Fields: fields, Decoded: pretty})
		return
	}
	s.page(w, 200, "autopost", t, pageData{Target: target, Fields: fields})
}

type keyStore struct {
	key  *rsa.PrivateKey
	cert []byte
}

func (k keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) { return k.key, k.cert, nil }

// signEl adds an enveloped signature right after the element's Issuer, where
// the SAML schema wants it.
func signEl(el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate, sha1 bool) error {
	ctx := dsig.NewDefaultSigningContext(keyStore{key, cert.Raw})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if sha1 {
		if err := ctx.SetSignatureMethod(dsig.RSASHA1SignatureMethod); err != nil {
			return err
		}
	}
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return err
	}
	el.InsertChildAt(1, sig)
	return nil
}

// userField resolves an attribute mapping's field for a user.
func userField(t *Tenant, u *User, field string) []string {
	var v []string
	switch field {
	case "id":
		v = []string{u.ID}
	case "username":
		v = []string{u.UserName}
	case "email":
		v = []string{u.Email}
	case "givenName":
		v = []string{u.GivenName}
	case "familyName":
		v = []string{u.FamilyName}
	case "displayName":
		v = []string{u.DisplayName}
	case "title":
		v = []string{u.Title}
	case "department":
		v = []string{u.Department}
	case "phone":
		v = []string{u.Phone}
	case "employeeNumber":
		v = []string{u.EmployeeNumber}
	case "manager":
		v = []string{u.Manager}
	case "tenantId":
		v = []string{t.ExternalID}
	case "groups", "groupIds":
		for _, g := range t.groupsOf(u.ID) {
			if field == "groups" {
				v = append(v, g.Name)
			} else {
				v = append(v, g.ID)
			}
		}
	default:
		if k, ok := strings.CutPrefix(field, "attr."); ok {
			v = []string{u.Attributes[k]}
		} else if c, ok := strings.CutPrefix(field, "const:"); ok {
			v = []string{c}
		}
	}
	out := v[:0]
	for _, x := range v {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func nameIDValue(app *App, u *User) string {
	switch app.NameIDSource {
	case "id":
		return u.ID
	case "username":
		return u.UserName
	case "persistent":
		return pairwise(app.EntityID, u.ID)
	}
	if u.Email == "" {
		return u.UserName
	}
	return u.Email
}

var samlStatusFor = map[string]string{
	"access_denied": "RequestDenied", "consent_required": "RequestDenied",
	"login_required": "NoPassive", "interaction_required": "NoPassive",
}

// samlResponse builds and signs a Response, applying the SAML simulations.
// With errCode set it builds a failed Response with no assertion.
func (s *Server) samlResponse(t *Tenant, app *App, u *User, inResponseTo, errCode string, e *LogEntry) (string, error) {
	sims := t.Sims
	now := time.Now().UTC().Add(time.Duration(sims.ClockSkewSec) * time.Second)
	if sims.ClockSkewSec != 0 {
		e.note("simulated clock skew: %+ds", sims.ClockSkewSec)
	}
	issuer, audience, dest, recipient := s.samlIssuer(t, app), app.EntityID, app.ACSURL, app.ACSURL
	if sims.SAMLWrongIssuer {
		issuer = "https://wrong-issuer.example"
		e.warn("simulation: issuer is %s", issuer)
	}
	if sims.SAMLWrongAudience {
		audience = "https://wrong-audience.example"
		e.warn("simulation: audience is %s", audience)
	}
	if sims.SAMLWrongDestination {
		dest = "https://wrong-destination.example/acs"
		e.warn("simulation: Destination is %s", dest)
	}
	if sims.SAMLWrongRecipient {
		recipient = "https://wrong-recipient.example/acs"
		e.warn("simulation: Recipient is %s", recipient)
	}
	if sims.SAMLWrongInResponseTo {
		inResponseTo = samlID()
		e.warn("simulation: InResponseTo is %s, a request the SP never sent", inResponseTo)
	}
	issued, notBefore, notAfter := now, now.Add(-5*time.Minute), now.Add(5*time.Minute)
	if sims.SAMLExpired {
		issued, notBefore, notAfter = now.Add(-15*time.Minute), now.Add(-20*time.Minute), now.Add(-10*time.Minute)
		e.warn("simulation: assertion expired 10 minutes ago")
	}
	if sims.SAMLNotYetValid {
		notBefore, notAfter = now.Add(10*time.Minute), now.Add(20*time.Minute)
		e.warn("simulation: assertion is valid only from 10 minutes from now")
	}
	key, cert := t.key, t.cert
	if sims.SAMLWrongCert {
		key, cert = t.key2, t.cert2
		e.warn("simulation: signed with a certificate that is not in the metadata")
	}
	sign := !sims.SAMLUnsigned
	if !sign {
		e.warn("simulation: nothing is signed")
	}
	sha1 := sims.SAMLSHA1 || app.SigAlg == "sha1"

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", samlID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", issued.Format(samlTime))
	resp.CreateAttr("Destination", dest)
	if inResponseTo != "" {
		resp.CreateAttr("InResponseTo", inResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(issuer)
	st := resp.CreateElement("samlp:Status")
	sc := st.CreateElement("samlp:StatusCode")

	if errCode != "" {
		sub := samlStatusFor[errCode]
		if sub == "" {
			sub = "AuthnFailed"
		}
		sc.CreateAttr("Value", nsStatus+"Responder")
		sc.CreateElement("samlp:StatusCode").CreateAttr("Value", nsStatus+sub)
		st.CreateElement("samlp:StatusMessage").SetText(errCode)
		if sign && app.SignResponse {
			if err := signEl(resp, key, cert, sha1); err != nil {
				return "", err
			}
		}
		return doc.WriteToString()
	}
	sc.CreateAttr("Value", nsStatus+"Success")

	as := etree.NewElement("saml:Assertion")
	as.CreateAttr("xmlns:saml", nsAssertion)
	as.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	as.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	as.CreateAttr("ID", samlID())
	as.CreateAttr("IssueInstant", issued.Format(samlTime))
	as.CreateAttr("Version", "2.0")
	as.CreateElement("saml:Issuer").SetText(issuer)
	subj := as.CreateElement("saml:Subject")
	if sims.SAMLMissingNameID {
		e.warn("simulation: no NameID")
	} else {
		nid := subj.CreateElement("saml:NameID")
		nid.CreateAttr("Format", app.NameIDFormat)
		nid.SetText(nameIDValue(app, u))
		if sims.SAMLCommentInjection {
			nid.SetText(nameIDValue(app, u) + ".evil.example") // the comment goes in after signing
		}
	}
	conf := subj.CreateElement("saml:SubjectConfirmation")
	conf.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	data := conf.CreateElement("saml:SubjectConfirmationData")
	if inResponseTo != "" {
		data.CreateAttr("InResponseTo", inResponseTo)
	}
	data.CreateAttr("NotOnOrAfter", notAfter.Format(samlTime))
	data.CreateAttr("Recipient", recipient)
	cond := as.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", notBefore.Format(samlTime))
	cond.CreateAttr("NotOnOrAfter", notAfter.Format(samlTime))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)
	authn := as.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", now.Format(samlTime))
	authn.CreateAttr("SessionIndex", samlID())
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	if sims.SAMLNoAttributes {
		e.warn("simulation: no attributes")
	} else if len(app.Attributes) > 0 {
		stmt := as.CreateElement("saml:AttributeStatement")
		for _, m := range app.Attributes {
			vals := userField(t, u, m.Field)
			if len(vals) == 0 {
				continue
			}
			a := stmt.CreateElement("saml:Attribute")
			a.CreateAttr("Name", m.Name)
			if app.AttrNameFormat != "" {
				a.CreateAttr("NameFormat", app.AttrNameFormat)
			}
			for _, v := range vals {
				av := a.CreateElement("saml:AttributeValue")
				av.CreateAttr("xsi:type", "xs:string")
				av.SetText(v)
			}
		}
		if len(stmt.ChildElements()) == 0 {
			as.RemoveChild(stmt)
		}
	}

	if sign && app.SignAssertion {
		if err := signEl(as, key, cert, sha1); err != nil {
			return "", err
		}
	}
	resp.AddChild(as)
	if sign && app.SignResponse {
		if err := signEl(resp, key, cert, sha1); err != nil {
			return "", err
		}
	}
	if sims.SAMLSignatureWrapping {
		evil := as.Copy()
		if sig := child(evil, "Signature"); sig != nil {
			evil.RemoveChild(sig)
		}
		evil.RemoveAttr("ID")
		evil.CreateAttr("ID", samlID())
		if nid := find(evil, "NameID"); nid != nil {
			nid.SetText("attacker@evil.example")
		}
		resp.InsertChildAt(as.Index(), evil) // after signing: an attacker cannot re-sign
		e.warn("simulation: signature wrapping, a forged unsigned assertion for attacker@evil.example comes first")
	}
	if nid := find(as, "NameID"); nid != nil && sims.SAMLCommentInjection {
		// Comments are not part of the signed bytes, so the signature stays valid.
		nid.SetText(nameIDValue(app, u))
		nid.CreateComment("mock-idp")
		nid.CreateText(".evil.example")
		e.warn("simulation: NameID is %s<!--mock-idp-->.evil.example; the signature still verifies", nameIDValue(app, u))
	}
	if sims.SAMLBadSignature {
		if nid := find(as, "NameID"); nid != nil {
			nid.SetText("attacker@evil.example")
		} else {
			find(as, "Audience").SetText("tampered")
		}
		e.warn("simulation: NameID changed to attacker@evil.example after signing")
	}
	if sign {
		e.note("signed: response=%v assertion=%v alg=%s", app.SignResponse, app.SignAssertion, map[bool]string{true: "rsa-sha1", false: "rsa-sha256"}[sha1])
	}
	return doc.WriteToString()
}

func (s *Server) samlSLO(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "saml.slo"
	r.ParseForm()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t, app := s.samlApp(w, r)
	if t == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie(t.ID), Path: "/t/" + t.ID, MaxAge: -1})
	e.note("IdP session cleared")
	raw := r.Form.Get("SAMLRequest")
	if raw == "" {
		s.page(w, 200, "message", t, pageData{Title: "Signed out", Info: "Your " + providers[t.Provider].Name + " session has ended."})
		return
	}
	x, err := decodeSAMLMessage(raw)
	if err != nil {
		s.errorPage(w, r, t, 400, "Bad LogoutRequest", err.Error())
		return
	}
	e.decode("LogoutRequest", "xml", prettyXML(x))
	doc := etree.NewDocument()
	if err := doc.ReadFromString(x); err != nil || doc.Root() == nil {
		s.errorPage(w, r, t, 400, "Bad LogoutRequest", "not XML")
		return
	}
	if app.SLOURL == "" {
		e.warn("app has no SLO URL, so no LogoutResponse was sent")
		s.page(w, 200, "message", t, pageData{Title: "Signed out", Info: "Set the app's SLO URL to receive a LogoutResponse."})
		return
	}
	out := etree.NewDocument()
	lr := out.CreateElement("samlp:LogoutResponse")
	lr.CreateAttr("xmlns:samlp", nsProtocol)
	lr.CreateAttr("xmlns:saml", nsAssertion)
	lr.CreateAttr("ID", samlID())
	lr.CreateAttr("Version", "2.0")
	lr.CreateAttr("IssueInstant", time.Now().UTC().Format(samlTime))
	lr.CreateAttr("Destination", app.SLOURL)
	lr.CreateAttr("InResponseTo", doc.Root().SelectAttrValue("ID", ""))
	lr.CreateElement("saml:Issuer").SetText(s.samlIssuer(t, app))
	lr.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", nsStatus+"Success")
	if r.Method == http.MethodGet {
		// The request came by HTTP-Redirect, so answer the same way, as real
		// IdPs do. In this binding the signature is over the query string,
		// not inside the XML (SAML bindings §3.4.4.1).
		xs, _ := out.WriteToString()
		e.decode("SAMLResponse", "xml", prettyXML(xs))
		q := "SAMLResponse=" + url.QueryEscape(deflateB64(xs))
		if rs := r.Form.Get("RelayState"); rs != "" {
			q += "&RelayState=" + url.QueryEscape(rs)
		}
		if !t.Sims.SAMLUnsigned {
			q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
			sum := sha256.Sum256([]byte(q))
			sig, err := rsa.SignPKCS1v15(rand.Reader, t.key, crypto.SHA256, sum[:])
			if err != nil {
				s.errorPage(w, r, t, 500, "Could not sign", err.Error())
				return
			}
			q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
		}
		sep := "?"
		if strings.Contains(app.SLOURL, "?") {
			sep = "&"
		}
		e.note("LogoutResponse sent by HTTP-Redirect, matching the request's binding")
		http.Redirect(w, r, app.SLOURL+sep+q, http.StatusFound)
		return
	}
	if !t.Sims.SAMLUnsigned {
		if err := signEl(lr, t.key, t.cert, false); err != nil {
			s.errorPage(w, r, t, 500, "Could not sign", err.Error())
			return
		}
	}
	xs, _ := out.WriteToString()
	s.postToSP(w, r, t, app.SLOURL, "SAMLResponse", xs, r.Form.Get("RelayState"))
}
