package main

import (
	"fmt"
	"reflect"
	"strings"
)

// Simulations are per-tenant faults and behaviours. The zero value is a
// healthy IdP.
type Simulations struct {
	LatencyMs       int    `json:"latencyMs"`
	HTTPStatus      int    `json:"httpStatus"`
	ClockSkewSec    int    `json:"clockSkewSec"`
	Once            bool   `json:"once"`
	AutoLogin       string `json:"autoLogin"`
	PauseBeforeSend bool   `json:"pauseBeforeSend"`
	AnyPassword     bool   `json:"anyPassword"`
	RequireMFA      bool   `json:"requireMfa"`
	ShowConsent     bool   `json:"showConsent"`
	LockedOut       bool   `json:"lockedOut"`
	AuthError       string `json:"authError"`
	TokenError      string `json:"tokenError"`

	SAMLUnsigned          bool `json:"samlUnsigned"`
	SAMLBadSignature      bool `json:"samlBadSignature"`
	SAMLWrongCert         bool `json:"samlWrongCert"`
	SAMLSHA1              bool `json:"samlSha1"`
	SAMLSignatureWrapping bool `json:"samlSignatureWrapping"`
	SAMLCommentInjection  bool `json:"samlCommentInjection"`
	SAMLWrongIssuer       bool `json:"samlWrongIssuer"`
	SAMLWrongAudience     bool `json:"samlWrongAudience"`
	SAMLWrongDestination  bool `json:"samlWrongDestination"`
	SAMLWrongRecipient    bool `json:"samlWrongRecipient"`
	SAMLWrongInResponseTo bool `json:"samlWrongInResponseTo"`
	SAMLExpired           bool `json:"samlExpired"`
	SAMLNotYetValid       bool `json:"samlNotYetValid"`
	SAMLMissingNameID     bool `json:"samlMissingNameId"`
	SAMLNoAttributes      bool `json:"samlNoAttributes"`

	OIDCExpired         bool `json:"oidcExpired"`
	OIDCWrongIssuer     bool `json:"oidcWrongIssuer"`
	OIDCWrongAudience   bool `json:"oidcWrongAudience"`
	OIDCBadSignature    bool `json:"oidcBadSignature"`
	OIDCAlgNone         bool `json:"oidcAlgNone"`
	OIDCUnknownKid      bool `json:"oidcUnknownKid"`
	OIDCWrongNonce      bool `json:"oidcWrongNonce"`
	OIDCWrongAtHash     bool `json:"oidcWrongAtHash"`
	OIDCWrongState      bool `json:"oidcWrongState"`
	OIDCMissingEmail    bool `json:"oidcMissingEmail"`
	OIDCEmailUnverified bool `json:"oidcEmailUnverified"`
}

type simInfo struct {
	Key     string   `json:"key"`
	Group   string   `json:"group"`
	Label   string   `json:"label"`
	Desc    string   `json:"desc"`
	Type    string   `json:"type"` // bool | int | string | user
	Options []string `json:"options,omitempty"`
}

func sim(key, group, typ, label, desc string, opts ...string) simInfo {
	return simInfo{key, group, label, desc, typ, opts}
}

var oauthErrors = []string{"access_denied", "login_required", "consent_required", "interaction_required", "invalid_scope", "unauthorized_client", "server_error", "temporarily_unavailable"}
var tokenErrors = []string{"invalid_grant", "invalid_client", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "server_error"}

var simCatalog = []simInfo{
	sim("latencyMs", "Network", "int", "Latency (ms)", "Delay every IdP endpoint: authorize, token, SAML, metadata, JWKS."),
	sim("httpStatus", "Network", "int", "Outage status", "Answer every IdP endpoint with this HTTP status, e.g. 500 or 503. 0 is off."),
	sim("clockSkewSec", "Network", "int", "Clock skew (s)", "Shift every timestamp the IdP issues. Positive means the IdP clock runs ahead."),
	sim("once", "Behaviour", "bool", "One shot", "Clear every fault after the next completed sign-in or token call. Good for tests."),
	sim("autoLogin", "Login flow", "user", "Auto sign-in as", "Skip the login page and sign in as this user. Best for automated tests."),
	sim("pauseBeforeSend", "Login flow", "bool", "Pause before send", "Show what is about to go to the app, decoded, and wait for a click."),
	sim("anyPassword", "Login flow", "bool", "Accept any password", "Any password works for any active user."),
	sim("requireMfa", "Login flow", "bool", "Require MFA", "Ask for a 6-digit code after the password. 000000 fails."),
	sim("showConsent", "Login flow", "bool", "Consent screen (OIDC)", "Ask the user to approve scopes. Deny returns access_denied."),
	sim("lockedOut", "Login flow", "bool", "Account locked", "Every sign-in fails with 'account locked'."),
	sim("authError", "Login flow", "string", "Fail sign-in with", "Return this error instead of signing in. OIDC gets error= on the redirect; SAML gets a Responder status.", oauthErrors...),
	sim("tokenError", "OIDC", "string", "Token endpoint error", "The token endpoint answers 400 with this error.", tokenErrors...),
	sim("samlUnsigned", "SAML", "bool", "Unsigned", "Sign nothing."),
	sim("samlBadSignature", "SAML", "bool", "Tampered after signing", "Change the NameID after signing. The digest no longer matches."),
	sim("samlWrongCert", "SAML", "bool", "Unknown signing cert", "Sign with a key that is not in the metadata, as after an unannounced rotation."),
	sim("samlSha1", "SAML", "bool", "SHA-1 signature", "Sign with rsa-sha1. Many SPs now reject it."),
	sim("samlSignatureWrapping", "SAML", "bool", "Signature wrapping (XSW)", "Put a forged, unsigned assertion before the signed one."),
	sim("samlCommentInjection", "SAML", "bool", "Comment in NameID", "NameID becomes user@domain<!---->.evil.example. Parsers that read only the first text node see user@domain."),
	sim("samlWrongIssuer", "SAML", "bool", "Wrong issuer", ""),
	sim("samlWrongAudience", "SAML", "bool", "Wrong audience", ""),
	sim("samlWrongDestination", "SAML", "bool", "Wrong Destination", ""),
	sim("samlWrongRecipient", "SAML", "bool", "Wrong Recipient", ""),
	sim("samlWrongInResponseTo", "SAML", "bool", "Wrong InResponseTo", "Reply to an AuthnRequest the SP never sent."),
	sim("samlExpired", "SAML", "bool", "Expired assertion", "NotOnOrAfter is 10 minutes in the past."),
	sim("samlNotYetValid", "SAML", "bool", "Not yet valid", "NotBefore is 10 minutes in the future."),
	sim("samlMissingNameId", "SAML", "bool", "No NameID", ""),
	sim("samlNoAttributes", "SAML", "bool", "No attributes", "Send no AttributeStatement."),
	sim("oidcExpired", "OIDC", "bool", "Expired ID token", "exp is one hour in the past."),
	sim("oidcWrongIssuer", "OIDC", "bool", "Wrong iss", ""),
	sim("oidcWrongAudience", "OIDC", "bool", "Wrong aud", ""),
	sim("oidcBadSignature", "OIDC", "bool", "Tampered ID token", "Change the email claim after signing."),
	sim("oidcAlgNone", "OIDC", "bool", "alg=none", "Unsigned ID token. An app that accepts it lets anyone sign in as anyone."),
	sim("oidcUnknownKid", "OIDC", "bool", "Unknown kid", "Sign with a key that is not in the JWKS."),
	sim("oidcWrongNonce", "OIDC", "bool", "Wrong nonce", ""),
	sim("oidcWrongAtHash", "OIDC", "bool", "Wrong at_hash", ""),
	sim("oidcWrongState", "OIDC", "bool", "Wrong state", "Return a different state, as a CSRF attempt would."),
	sim("oidcMissingEmail", "OIDC", "bool", "No email claim", "As Entra does for users without a mailbox."),
	sim("oidcEmailUnverified", "OIDC", "bool", "email_verified=false", ""),
}

type preset struct {
	Key   string         `json:"key"`
	Label string         `json:"label"`
	Set   map[string]any `json:"set"`
}

var presets = []preset{
	{"outage", "Outage (503)", map[string]any{"httpStatus": 503}},
	{"slow", "Slow IdP (4 s)", map[string]any{"latencyMs": 4000}},
	{"skew-ahead", "Clock 5 min ahead", map[string]any{"clockSkewSec": 300}},
	{"skew-behind", "Clock 5 min behind", map[string]any{"clockSkewSec": -300}},
	{"expired", "Expired assertion and token", map[string]any{"samlExpired": true, "oidcExpired": true}},
	{"tampered", "Tampered signature", map[string]any{"samlBadSignature": true, "oidcBadSignature": true}},
	{"rotated", "Unannounced key rotation", map[string]any{"samlWrongCert": true, "oidcUnknownKid": true}},
	{"wrong-audience", "Wrong audience", map[string]any{"samlWrongAudience": true, "oidcWrongAudience": true}},
	{"unsigned", "Nothing signed", map[string]any{"samlUnsigned": true, "oidcAlgNone": true}},
	{"xsw", "Signature wrapping attack", map[string]any{"samlSignatureWrapping": true}},
	{"denied", "User denies access", map[string]any{"authError": "access_denied"}},
	{"mfa", "MFA and consent", map[string]any{"requireMfa": true, "showConsent": true}},
	{"no-email", "Missing email (Entra style)", map[string]any{"oidcMissingEmail": true}},
	{"unverified", "Unverified email", map[string]any{"oidcEmailUnverified": true}},
}

// activeSims lists every non-default simulation, for logs and banners.
func activeSims(s Simulations) []string {
	out := []string{}
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.IsZero() {
			continue
		}
		name := strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0]
		if f.Kind() == reflect.Bool {
			out = append(out, name)
		} else {
			out = append(out, fmt.Sprintf("%s=%v", name, f.Interface()))
		}
	}
	return out
}

// consumeOnce clears the faults after a completed flow when "once" is set.
// Callers hold store.mu.
func (s *Server) consumeOnce(t *Tenant) {
	if !t.Sims.Once {
		return
	}
	t.Sims = Simulations{AutoLogin: t.Sims.AutoLogin}
	s.store.save()
	s.logs.publish("change", map[string]string{"tenant": t.ID})
}
