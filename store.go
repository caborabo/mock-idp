package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Store is the whole persistent state. One mutex guards all of it.
type Store struct {
	mu      sync.Mutex
	path    string
	Tenants []*Tenant `json:"tenants"`

	// The built-in test SP's key pair: it signs the test SP's AuthnRequests
	// and decrypts encrypted assertions sent to it.
	SPKeyPEM  string `json:"spKeyPem"`
	SPCertPEM string `json:"spCertPem"`
	spKey     *rsa.PrivateKey
}

func loadStore(path string) (*Store, error) {
	s := &Store{path: path}
	if path == "" {
		return s, s.ensureSPKey()
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.ensureSPKey()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, t := range s.Tenants {
		if err := t.loadKeys(); err != nil {
			return nil, fmt.Errorf("tenant %s: %w", t.ID, err)
		}
	}
	return s, s.ensureSPKey()
}

func (s *Store) ensureSPKey() error {
	if s.SPKeyPEM == "" {
		var err error
		if s.SPKeyPEM, s.SPCertPEM, err = newKeyPair("mock-idp built-in test SP"); err != nil {
			return err
		}
	}
	var err error
	s.spKey, err = parseKey(s.SPKeyPEM)
	return err
}

// save writes the state file. Callers hold mu.
func (s *Store) save() {
	if s.path == "" {
		return
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	os.MkdirAll(filepath.Dir(s.path), 0o755)
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("save state: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("save state: %v", err)
	}
}

func (s *Store) tenant(id string) *Tenant {
	for _, t := range s.Tenants {
		if t.ID == id {
			return t
		}
	}
	return nil
}

type Tenant struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Provider    string        `json:"provider"`
	Domain      string        `json:"domain"`
	ExternalID  string        `json:"externalId"` // Entra tenant id, Okta org id, Google idpid…
	Users       []*User       `json:"users"`
	Groups      []*Group      `json:"groups"`
	Apps        []*App        `json:"apps"`
	ScimTargets []*ScimTarget `json:"scimTargets"`
	Sims        Simulations   `json:"simulations"`
	KeyPEM      string        `json:"keyPem,omitempty"`
	CertPEM     string        `json:"certPem"`
	Key2PEM     string        `json:"key2Pem,omitempty"` // the "wrong" key: not published anywhere
	Cert2PEM    string        `json:"cert2Pem,omitempty"`
	Created     time.Time     `json:"created"`

	key, key2   *rsa.PrivateKey
	cert, cert2 *x509.Certificate
}

type User struct {
	ID             string            `json:"id"`
	UserName       string            `json:"userName"`
	Email          string            `json:"email"`
	EmailVerified  bool              `json:"emailVerified"`
	GivenName      string            `json:"givenName"`
	FamilyName     string            `json:"familyName"`
	DisplayName    string            `json:"displayName"`
	Password       string            `json:"password"`
	Active         bool              `json:"active"`
	Title          string            `json:"title,omitempty"`
	Department     string            `json:"department,omitempty"`
	Phone          string            `json:"phone,omitempty"`
	EmployeeNumber string            `json:"employeeNumber,omitempty"`
	Manager        string            `json:"manager,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type App struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // saml | oidc

	EntityID       string        `json:"entityId,omitempty"`
	ACSURL         string        `json:"acsUrl,omitempty"`
	SLOURL         string        `json:"sloUrl,omitempty"`
	Issuer         string        `json:"issuer,omitempty"` // overrides the provider's issuer format
	NameIDFormat   string        `json:"nameIdFormat,omitempty"`
	NameIDSource   string        `json:"nameIdSource,omitempty"` // email | username | id | persistent
	SignResponse   bool          `json:"signResponse"`
	SignAssertion  bool          `json:"signAssertion"`
	SigAlg         string        `json:"sigAlg,omitempty"` // sha256 | sha1
	Attributes     []AttrMapping `json:"attributes,omitempty"`
	AttrNameFormat string        `json:"attrNameFormat,omitempty"`
	RelayState     string        `json:"relayState,omitempty"`

	EncryptAssertion      bool   `json:"encryptAssertion"`
	SPEncryptionCert      string `json:"spEncryptionCert,omitempty"` // PEM, base64 DER, or the SP's metadata XML
	EncryptionAlg         string `json:"encryptionAlg,omitempty"`    // aes128-cbc | aes256-cbc | aes128-gcm | aes256-gcm
	KeyTransportAlg       string `json:"keyTransportAlg,omitempty"`  // rsa-oaep | rsa-1_5
	SPSigningCert         string `json:"spSigningCert,omitempty"`    // verifies signed AuthnRequests
	RequireSignedRequests bool   `json:"requireSignedRequests"`

	ClientID       string   `json:"clientId,omitempty"`
	ClientSecret   string   `json:"clientSecret,omitempty"`
	RedirectURIs   []string `json:"redirectUris,omitempty"`
	PostLogoutURIs []string `json:"postLogoutRedirectUris,omitempty"`
	Public         bool     `json:"public"` // SPA or native: no secret
	RequirePKCE    bool     `json:"requirePkce"`
	GroupsClaim    bool     `json:"groupsClaim"`
	IDTokenTTL     int      `json:"idTokenTtl,omitempty"`
	AccessTokenTTL int      `json:"accessTokenTtl,omitempty"`
}

type ScimTarget struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	BaseURL    string            `json:"baseUrl"`
	Token      string            `json:"token"`
	Flavor     string            `json:"flavor"` // provider whose SCIM client to imitate
	AutoPush   bool              `json:"autoPush"`
	UserMap    map[string]string `json:"userMap"` // local id -> id on the app
	GroupMap   map[string]string `json:"groupMap"`
	LastResult *ScimRun          `json:"lastResult,omitempty"`
}

func (t *Tenant) user(ref string) *User {
	for _, u := range t.Users {
		if u.ID == ref {
			return u
		}
	}
	for _, u := range t.Users {
		if ref != "" && (strings.EqualFold(u.UserName, ref) || strings.EqualFold(u.Email, ref)) {
			return u
		}
	}
	return nil
}

func (t *Tenant) group(ref string) *Group {
	for _, g := range t.Groups {
		if g.ID == ref || strings.EqualFold(g.Name, ref) {
			return g
		}
	}
	return nil
}

func (t *Tenant) app(id string) *App {
	for _, a := range t.Apps {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func (t *Tenant) appByClientID(cid string) *App {
	for _, a := range t.Apps {
		if a.Type == "oidc" && cid != "" && a.ClientID == cid {
			return a
		}
	}
	return nil
}

func (t *Tenant) target(id string) *ScimTarget {
	for _, g := range t.ScimTargets {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func (t *Tenant) groupsOf(uid string) []*Group {
	var out []*Group
	for _, g := range t.Groups {
		if slices.Contains(g.Members, uid) {
			out = append(out, g)
		}
	}
	return out
}

// ---- keys ----

func newKeyPair(cn string) (keyPEM, certPEM string, err error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"mock-idp"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return "", "", err
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return keyPEM, certPEM, nil
}

func (t *Tenant) loadKeys() error {
	var err error
	if t.key, err = parseKey(t.KeyPEM); err != nil {
		return err
	}
	if t.key2, err = parseKey(t.Key2PEM); err != nil {
		return err
	}
	if t.cert, err = parseCert(t.CertPEM); err != nil {
		return err
	}
	t.cert2, err = parseCert(t.Cert2PEM)
	return err
}

func parseKey(p string) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("missing private key")
	}
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}

func parseCert(p string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("missing certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func kid(k *rsa.PublicKey) string {
	sum := sha256.Sum256(k.N.Bytes())
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// ---- ids ----

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const digits = "0123456789"

func randFrom(chars string, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// newID makes an id shaped like the provider's own, so apps that assume a
// format (or wrongly assume an email) find out here.
func newID(style, kind string) string {
	switch style {
	case "okta":
		return map[string]string{"user": "00u", "group": "00g", "app": "0oa", "org": "00o"}[kind] + randFrom(alnum, 17)
	case "google":
		return "1" + randFrom(digits, 20)
	case "numeric":
		return randFrom("123456789", 1) + randFrom(digits, 8)
	case "hex":
		return randHex(12)
	case "auth0":
		if kind == "user" {
			return "auth0|" + randHex(12)
		}
		return randHex(12)
	}
	return newUUID()
}

func clientIDFor(provider string) string {
	switch provider {
	case "okta":
		return newID("okta", "app")
	case "entra", "adfs":
		return newUUID()
	case "google":
		return randFrom(digits, 12) + "-" + strings.ToLower(randFrom(alnum, 32)) + ".apps.googleusercontent.com"
	}
	return randFrom(alnum, 32)
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func uniqueID(base string, taken func(string) bool) string {
	if base == "" {
		base = randHex(3)
	}
	id := base
	for i := 2; taken(id); i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	return id
}

// ---- tenants ----

func (s *Server) newTenant(id, name, provider, domain string, seed bool) (*Tenant, error) {
	p := providers[provider]
	if p == nil {
		return nil, errf(400, "unknown provider %q", provider)
	}
	if domain == "" {
		domain = slug(name) + ".example"
	}
	t := &Tenant{ID: id, Name: name, Provider: provider, Domain: domain, Created: time.Now().UTC(),
		Users: []*User{}, Groups: []*Group{}, Apps: []*App{}, ScimTargets: []*ScimTarget{}}
	switch provider {
	case "okta":
		t.ExternalID = newID("okta", "org")
	case "google":
		t.ExternalID = "C0" + randFrom(alnum, 7)
	default:
		t.ExternalID = newUUID()
	}
	var err error
	if t.KeyPEM, t.CertPEM, err = newKeyPair(name + " signing"); err != nil {
		return nil, err
	}
	if t.Key2PEM, t.Cert2PEM, err = newKeyPair(name + " unpublished"); err != nil {
		return nil, err
	}
	if err := t.loadKeys(); err != nil {
		return nil, err
	}
	if seed {
		s.seedTenant(t)
	}
	return t, nil
}

// seedTenant adds users chosen to break naive apps: a deactivated user, an
// unverified email, a guest from another domain, non-ASCII names.
func (s *Server) seedTenant(t *Tenant) {
	p := providers[t.Provider]
	d := t.Domain
	mk := func(login, given, family, title, dept string) *User {
		u := &User{ID: newID(p.IDStyle, "user"), UserName: login + "@" + d, Email: login + "@" + d, EmailVerified: true,
			GivenName: given, FamilyName: family, DisplayName: given + " " + family, Password: "password", Active: true,
			Title: title, Department: dept, EmployeeNumber: randFrom(digits, 5)}
		t.Users = append(t.Users, u)
		return u
	}
	alice := mk("alice", "Alice", "Anderson", "Engineering Manager", "Engineering")
	alice.Phone = "+1 555 0100"
	alice.Attributes = map[string]string{"roles": "admin"}
	bob := mk("bob", "Bob", "Brown", "Software Engineer", "Engineering")
	bob.Manager = alice.ID
	carol := mk("carol", "Carol", "Chen", "Designer", "Design")
	carol.Active = false
	dave := mk("dave", "Dave", "Dubois", "Account Executive", "Sales")
	dave.EmailVerified = false
	mk("zoe", "Zoë", "Ñúñez-O'Brien", "Marketing Lead", "Marketing")
	guest := mk("sam", "Sam", "Partner", "Contractor", "")
	guest.Email = "sam@partner.example"
	guest.UserName = "sam@partner.example"
	if t.Provider == "entra" {
		guest.UserName = "sam_partner.example#EXT#@" + d // how Entra names B2B guests
		dave.Email = ""                                  // many Entra users have no mail attribute
	}

	var all []string
	for _, u := range t.Users {
		all = append(all, u.ID)
	}
	g := func(name string, members ...string) *Group {
		return &Group{ID: newID(p.IDStyle, "group"), Name: name, Members: members}
	}
	t.Groups = []*Group{g("Everyone", all...), g("Engineering", alice.ID, bob.ID), g("Admins", alice.ID), g("Sales", dave.ID)}

	samlApp := &App{ID: "test-saml", Name: "Built-in test SP (SAML)", Type: "saml",
		EntityID: s.base + "/sp/saml/" + t.ID + "/test-saml", ACSURL: s.base + "/sp/saml/" + t.ID + "/test-saml/acs",
		SPSigningCert: s.store.SPCertPEM, SPEncryptionCert: s.store.SPCertPEM}
	oidcApp := &App{ID: "test-oidc", Name: "Built-in test app (OIDC)", Type: "oidc", GroupsClaim: true,
		RedirectURIs:   []string{s.base + "/sp/oidc/" + t.ID + "/test-oidc/callback"},
		PostLogoutURIs: []string{s.base + "/"}}
	applyAppDefaults(t, samlApp)
	applyAppDefaults(t, oidcApp)
	t.Apps = []*App{samlApp, oidcApp}
}

func applyAppDefaults(t *Tenant, a *App) {
	p := providers[t.Provider]
	if a.Type == "saml" {
		if a.NameIDFormat == "" {
			a.NameIDFormat = p.NameIDFormat
		}
		if a.NameIDSource == "" {
			a.NameIDSource = p.NameIDSource
		}
		if a.Attributes == nil {
			a.Attributes = slices.Clone(p.SAMLAttrs)
		}
		if a.AttrNameFormat == "" {
			a.AttrNameFormat = p.AttrNameFormat
		}
		if !a.SignResponse && !a.SignAssertion {
			a.SignResponse, a.SignAssertion = p.SignResponse, p.SignAssertion
		}
		if a.SigAlg == "" {
			a.SigAlg = "sha256"
		}
		if a.EncryptionAlg == "" {
			a.EncryptionAlg = "aes256-cbc"
		}
		if a.KeyTransportAlg == "" {
			a.KeyTransportAlg = "rsa-oaep"
		}
		return
	}
	if a.ClientID == "" {
		a.ClientID = clientIDFor(t.Provider)
	}
	if a.ClientSecret == "" && !a.Public {
		a.ClientSecret = randFrom(alnum, 40)
	}
}
