package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"
)

const (
	nidEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	nidUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	nidPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	nidTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

	attrBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	attrURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	attrUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

	claimsWS  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"
	claimsMS  = "http://schemas.microsoft.com/identity/claims/"
	claimsWS8 = "http://schemas.microsoft.com/ws/2008/06/identity/claims/"
)

// AttrMapping puts a user field into a SAML attribute. Fields: id, username,
// email, givenName, familyName, displayName, title, department, phone,
// employeeNumber, manager, groups, groupIds, tenantId, attr.<name>.
type AttrMapping struct {
	Name  string `json:"name"`
	Field string `json:"field"`
}

// ScimFlavor is how a provider's SCIM client talks to apps. The differences
// are where real integrations break.
type ScimFlavor struct {
	OpCase          string `json:"opCase"`          // lower ("replace") or title ("Replace")
	BoolStrings     bool   `json:"boolStrings"`     // PATCH booleans sent as "True"/"False"
	Update          string `json:"update"`          // PUT (whole user) or PATCH
	OnDelete        string `json:"onDelete"`        // deactivate | delete | deactivate+delete
	Probe           string `json:"probe"`           // list | random-filter
	RemoveMember    string `json:"removeMember"`    // filter-path | value-array
	MembersOnCreate bool   `json:"membersOnCreate"` // members in the group POST, or a PATCH after
}

type Provider struct {
	Key            string        `json:"key"`
	Name           string        `json:"name"`
	Color          string        `json:"color"`
	IDStyle        string        `json:"idStyle"`
	NameIDFormat   string        `json:"nameIdFormat"`
	NameIDSource   string        `json:"nameIdSource"`
	SAMLAttrs      []AttrMapping `json:"samlAttributes"`
	AttrNameFormat string        `json:"attrNameFormat"`
	SignResponse   bool          `json:"signResponse"`
	SignAssertion  bool          `json:"signAssertion"`
	Scim           ScimFlavor    `json:"scim"`
	Quirks         []string      `json:"quirks"`
}

var genericScim = ScimFlavor{OpCase: "lower", Update: "PATCH", OnDelete: "deactivate", Probe: "list", RemoveMember: "filter-path", MembersOnCreate: true}

var providerList = []*Provider{
	{
		Key: "okta", Name: "Okta", Color: "#007dc1", IDStyle: "okta",
		NameIDFormat: nidUnspecified, NameIDSource: "username",
		SAMLAttrs:      []AttrMapping{{"email", "email"}, {"firstName", "givenName"}, {"lastName", "familyName"}, {"groups", "groups"}},
		AttrNameFormat: attrUnspecified, SignResponse: true, SignAssertion: true,
		Scim: ScimFlavor{OpCase: "lower", Update: "PUT", OnDelete: "deactivate", Probe: "list", RemoveMember: "filter-path", MembersOnCreate: true},
		Quirks: []string{
			"sub is the Okta user id (00u…), not the email.",
			"The groups claim appears only when the app asks for it.",
			"SAML issuer is http://www.okta.com/<key>, different for every app.",
			"SCIM updates are a PUT of the whole user. Deprovisioning only deactivates (active=false); Okta never DELETEs users.",
		},
	},
	{
		Key: "entra", Name: "Microsoft Entra ID", Color: "#0078d4", IDStyle: "guid",
		NameIDFormat: nidEmail, NameIDSource: "username",
		SAMLAttrs: []AttrMapping{
			{claimsMS + "tenantid", "tenantId"}, {claimsMS + "objectidentifier", "id"}, {claimsMS + "displayname", "displayName"},
			{claimsWS + "emailaddress", "email"}, {claimsWS + "givenname", "givenName"}, {claimsWS + "surname", "familyName"},
			{claimsWS + "name", "username"}, {claimsWS8 + "groups", "groupIds"},
		},
		SignAssertion: true,
		Scim:          ScimFlavor{OpCase: "title", BoolStrings: true, Update: "PATCH", OnDelete: "deactivate+delete", Probe: "random-filter", RemoveMember: "value-array"},
		Quirks: []string{
			"sub is pairwise: different for every app. Key users on oid + tid.",
			"email is optional and unverified: missing for many users, and there is no email_verified claim.",
			"preferred_username is the UPN. Guests look like name_domain#EXT#@tenant.",
			"groups are object ids (GUIDs), not names.",
			"SAML issuer is https://sts.windows.net/<tenant id>/ and only the assertion is signed.",
			`SCIM PATCH ops are Title case ("Replace") and booleans are strings ("False"). It probes with a random userName filter first.`,
		},
	},
	{
		Key: "google", Name: "Google Workspace", Color: "#1a73e8", IDStyle: "google",
		NameIDFormat: nidUnspecified, NameIDSource: "email",
		SAMLAttrs: []AttrMapping{}, SignAssertion: true,
		Scim: genericScim,
		Quirks: []string{
			"sub is a 21-digit number. email_verified is always sent.",
			"hd names the Workspace domain. Check it if only one company may sign in.",
			"SAML sends no attributes until an admin maps them: only the NameID (primary email).",
			"Google pushes SCIM only to catalogue apps. The SCIM flavor here is generic.",
		},
	},
	{
		Key: "onelogin", Name: "OneLogin", Color: "#1c1f2a", IDStyle: "numeric",
		NameIDFormat: nidEmail, NameIDSource: "email",
		SAMLAttrs:      []AttrMapping{{"User.email", "email"}, {"User.FirstName", "givenName"}, {"User.LastName", "familyName"}, {"memberOf", "groups"}},
		AttrNameFormat: attrBasic, SignAssertion: true,
		Scim:   ScimFlavor{OpCase: "lower", Update: "PUT", OnDelete: "deactivate", Probe: "list", RemoveMember: "filter-path", MembersOnCreate: true},
		Quirks: []string{"SAML attributes are User.email, User.FirstName, User.LastName.", "Issuer is https://app.onelogin.com/saml/metadata/<uuid>.", "User ids are numbers."},
	},
	{
		Key: "pingone", Name: "PingOne", Color: "#b3282d", IDStyle: "uuid",
		NameIDFormat: nidUnspecified, NameIDSource: "email",
		SAMLAttrs:      []AttrMapping{{"email", "email"}, {"given_name", "givenName"}, {"family_name", "familyName"}},
		AttrNameFormat: attrBasic, SignAssertion: true,
		Scim:   genericScim,
		Quirks: []string{"Issuer is https://auth.pingone.com/<environment id>.", "Subject ids are UUIDs."},
	},
	{
		Key: "jumpcloud", Name: "JumpCloud", Color: "#2e7d6b", IDStyle: "hex",
		NameIDFormat: nidEmail, NameIDSource: "email",
		SAMLAttrs:      []AttrMapping{{"email", "email"}, {"firstname", "givenName"}, {"lastname", "familyName"}, {"memberOf", "groups"}},
		AttrNameFormat: attrUnspecified, SignResponse: true, SignAssertion: true,
		Scim:   ScimFlavor{OpCase: "lower", Update: "PATCH", OnDelete: "delete", Probe: "list", RemoveMember: "filter-path", MembersOnCreate: true},
		Quirks: []string{"Issuer is whatever the admin typed; the default is JumpCloud for every app.", "Deprovisioning DELETEs the user."},
	},
	{
		Key: "adfs", Name: "AD FS", Color: "#5e5e5e", IDStyle: "guid",
		NameIDFormat: nidUnspecified, NameIDSource: "username",
		SAMLAttrs: []AttrMapping{
			{claimsWS + "upn", "username"}, {claimsWS + "emailaddress", "email"}, {claimsWS + "givenname", "givenName"},
			{claimsWS + "surname", "familyName"}, {claimsWS + "name", "displayName"}, {claimsWS8 + "role", "groups"},
		},
		SignAssertion: true,
		Scim:          genericScim,
		Quirks:        []string{"On-premises. Issuer is http://<host>/adfs/services/trust.", "Groups arrive as role claims, by name.", "AD FS has no SCIM client; the flavor here is generic."},
	},
	{
		Key: "auth0", Name: "Auth0", Color: "#eb5424", IDStyle: "auth0",
		NameIDFormat: nidUnspecified, NameIDSource: "id",
		SAMLAttrs: []AttrMapping{
			{claimsWS + "nameidentifier", "id"}, {claimsWS + "emailaddress", "email"}, {claimsWS + "name", "displayName"},
			{claimsWS + "givenname", "givenName"}, {claimsWS + "surname", "familyName"}, {claimsWS + "upn", "email"},
		},
		AttrNameFormat: attrURI, SignAssertion: true,
		Scim:   genericScim,
		Quirks: []string{"sub is connection|id, e.g. auth0|64f…", "Issuer is urn:<tenant>.auth0.com."},
	},
	{
		Key: "keycloak", Name: "Keycloak", Color: "#4d4d4d", IDStyle: "uuid",
		NameIDFormat: nidUnspecified, NameIDSource: "username",
		SAMLAttrs:      []AttrMapping{{"email", "email"}, {"firstName", "givenName"}, {"lastName", "familyName"}, {"Role", "groups"}},
		AttrNameFormat: attrBasic, SignResponse: true, SignAssertion: true,
		Scim:   genericScim,
		Quirks: []string{"Groups in tokens are paths like /Engineering.", "preferred_username is always sent.", "Issuer is <base>/realms/<realm>."},
	},
	{
		Key: "generic", Name: "Generic SAML / OIDC", Color: "#6b7280", IDStyle: "uuid",
		NameIDFormat: nidEmail, NameIDSource: "email",
		SAMLAttrs:      []AttrMapping{{"email", "email"}, {"firstName", "givenName"}, {"lastName", "familyName"}, {"groups", "groups"}},
		AttrNameFormat: attrBasic, SignResponse: true, SignAssertion: true,
		Scim:   genericScim,
		Quirks: []string{"Plain, spec-shaped behaviour with no vendor quirks."},
	},
}

var providers = func() map[string]*Provider {
	m := map[string]*Provider{}
	for _, p := range providerList {
		m[p.Key] = p
	}
	return m
}()

func (s *Server) samlIssuer(t *Tenant, app *App) string {
	if app.Issuer != "" {
		return app.Issuer
	}
	switch t.Provider {
	case "okta":
		sum := sha256.Sum256([]byte(t.ID + "/" + app.ID))
		return "http://www.okta.com/exk" + strings.TrimRight(base64.RawURLEncoding.EncodeToString(sum[:12]), "-_")
	case "entra":
		return "https://sts.windows.net/" + t.ExternalID + "/"
	case "google":
		return "https://accounts.google.com/o/saml2?idpid=" + t.ExternalID
	case "onelogin":
		return "https://app.onelogin.com/saml/metadata/" + t.ExternalID
	case "pingone":
		return "https://auth.pingone.com/" + t.ExternalID
	case "jumpcloud":
		return "JumpCloud"
	case "adfs":
		return "http://" + t.Domain + "/adfs/services/trust"
	case "auth0":
		return "urn:" + t.ID + ".auth0.com"
	case "keycloak":
		return s.base + "/realms/" + t.ID
	}
	return s.base + "/t/" + t.ID + "/saml/" + app.ID
}

func pairwise(sector, id string) string {
	sum := sha256.Sum256([]byte(sector + "|" + id))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:43]
}

// subject is the sub claim for this user in this app.
func subject(t *Tenant, app *App, u *User) string {
	if t.Provider == "entra" {
		return pairwise(app.ClientID, u.ID)
	}
	return u.ID
}

// profileClaims are the identity claims a provider puts in the ID token and
// userinfo response, shaped the way that provider shapes them.
func profileClaims(t *Tenant, app *App, u *User, scopes map[string]bool) map[string]any {
	c := map[string]any{"sub": subject(t, app, u)}
	groups := t.groupsOf(u.ID)
	names := func(prefix string) []string {
		out := []string{}
		for _, g := range groups {
			out = append(out, prefix+g.Name)
		}
		return out
	}
	std := func() {
		if scopes["profile"] {
			c["name"], c["given_name"], c["family_name"], c["preferred_username"] = u.DisplayName, u.GivenName, u.FamilyName, u.UserName
		}
		if scopes["email"] && u.Email != "" {
			c["email"], c["email_verified"] = u.Email, u.EmailVerified
		}
	}
	switch t.Provider {
	case "entra":
		c["oid"], c["tid"], c["ver"] = u.ID, t.ExternalID, "2.0"
		c["preferred_username"] = u.UserName
		if scopes["profile"] {
			c["name"] = u.DisplayName
		}
		if scopes["email"] && u.Email != "" {
			c["email"] = u.Email // Entra sends no email_verified
		}
		if app.GroupsClaim {
			ids := []string{}
			for _, g := range groups {
				ids = append(ids, g.ID)
			}
			c["groups"] = ids
		}
		if r := u.Attributes["roles"]; r != "" {
			c["roles"] = strings.Split(r, ",")
		}
	case "google":
		std()
		delete(c, "preferred_username")
		if scopes["profile"] {
			c["picture"], c["locale"] = "https://www.gravatar.com/avatar/?d=identicon", "en"
		}
		if t.Domain != "" && strings.HasSuffix(u.Email, "@"+t.Domain) {
			c["hd"] = t.Domain
		}
	case "okta":
		std()
		c["ver"], c["idp"] = 1, t.ExternalID
		if scopes["profile"] {
			c["locale"], c["zoneinfo"], c["updated_at"] = "en_US", "America/Los_Angeles", time.Now().Add(-48*time.Hour).Unix()
		}
		if app.GroupsClaim || scopes["groups"] {
			c["groups"] = names("")
		}
	case "auth0":
		std()
		if scopes["profile"] {
			c["nickname"] = strings.Split(u.UserName, "@")[0]
			c["picture"] = "https://www.gravatar.com/avatar/?d=identicon"
			c["updated_at"] = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
		}
	case "keycloak":
		std()
		c["preferred_username"], c["typ"] = u.UserName, "ID"
		if app.GroupsClaim || scopes["groups"] {
			c["groups"] = names("/")
		}
		if r := u.Attributes["roles"]; r != "" {
			c["realm_access"] = map[string]any{"roles": strings.Split(r, ",")}
		}
	case "adfs":
		std()
		c["upn"], c["unique_name"] = u.UserName, strings.ToUpper(strings.Split(t.Domain, ".")[0])+`\`+strings.Split(u.UserName, "@")[0]
		if app.GroupsClaim {
			c["role"] = names("")
		}
	default:
		std()
		if app.GroupsClaim || scopes["groups"] {
			c["groups"] = names("")
		}
	}
	return c
}
