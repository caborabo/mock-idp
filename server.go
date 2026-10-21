package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"
)

const version = "0.1.0"

//go:embed web
var webRoot embed.FS

type Server struct {
	base     string
	store    *Store
	logs     *LogBook
	mux      *http.ServeMux
	routes   []*route
	apiToken string
	mem      memory
}

func newServer(base, dataPath, apiToken string) (*Server, error) {
	st, err := loadStore(dataPath)
	if err != nil {
		return nil, err
	}
	s := &Server{base: base, store: st, logs: newLogBook(2000), mux: http.NewServeMux(), apiToken: apiToken}
	s.mem.init()
	if len(st.Tenants) == 0 {
		s.store.mu.Lock()
		err := s.seed()
		s.store.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	s.registerIdP()
	s.registerSP()
	s.registerAPI()
	s.mux.HandleFunc("POST /mcp", s.mcp)
	s.mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "this MCP server answers POST only (no SSE stream)", http.StatusMethodNotAllowed)
	})
	s.mux.HandleFunc("GET /llms.txt", s.llmsTxt)
	web, _ := fs.Sub(webRoot, "web")
	s.mux.Handle("GET /", http.FileServerFS(web))
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

var seedTenants = []struct{ name, provider, domain string }{
	{"Acme Corp", "okta", "acme.example"},
	{"Contoso", "entra", "contoso.example"},
	{"Globex", "google", "globex.example"},
	{"Initech", "onelogin", "initech.example"},
	{"Umbrella", "pingone", "umbrella.example"},
	{"Hooli", "jumpcloud", "hooli.example"},
	{"Wayne Enterprises", "adfs", "wayne.example"},
	{"Stark Industries", "auth0", "stark.example"},
	{"Cyberdyne", "keycloak", "cyberdyne.example"},
}

// seed creates one demo tenant per provider. Callers hold store.mu.
func (s *Server) seed() error {
	for _, st := range seedTenants {
		t, err := s.newTenant(st.provider, st.name, st.provider, st.domain, true)
		if err != nil {
			return err
		}
		s.store.Tenants = append(s.store.Tenants, t)
	}
	s.store.save()
	return nil
}

// interaction is a sign-in in progress, shared by the OIDC and SAML flows.
type interaction struct {
	ID, Kind, Tenant, App string
	Created               time.Time

	RedirectURI, State, Nonce, Scope, ResponseType, ResponseMode string
	Challenge, ChallengeMethod, Prompt, LoginHint                string

	RequestID, RelayState string
	ForceAuthn, Passive   bool

	UserID             string
	MFADone, Consented bool
}

type authCode struct {
	Tenant, App, UserID, RedirectURI, Scope, Nonce, Challenge, Method string
	AuthTime, Created                                                 time.Time
	AMR                                                               []string
	Sims                                                              Simulations // as they were at sign-in, so "once" can clear them
}

type refreshGrant struct {
	Tenant, App, UserID, Scope string
	AuthTime                   time.Time
	AMR                        []string
}

type spPending struct {
	Tenant, App, Nonce, Verifier string
	Created                      time.Time
}

// memory holds short-lived protocol state.
// ponytail: entries leave only when used; abandoned logins leak slowly. Add a sweeper if instances run for weeks.
type memory struct {
	mu           sync.Mutex
	interactions map[string]*interaction
	codes        map[string]*authCode
	refresh      map[string]*refreshGrant
	sp           map[string]*spPending
}

func (m *memory) init() {
	m.interactions = map[string]*interaction{}
	m.codes = map[string]*authCode{}
	m.refresh = map[string]*refreshGrant{}
	m.sp = map[string]*spPending{}
}

func put[T any](m *memory, mp map[string]T, k string, v T) {
	m.mu.Lock()
	mp[k] = v
	m.mu.Unlock()
}

func take[T any](m *memory, mp map[string]T, k string) T {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := mp[k]
	delete(mp, k)
	return v
}

func peek[T any](m *memory, mp map[string]T, k string) T {
	m.mu.Lock()
	defer m.mu.Unlock()
	return mp[k]
}

type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return e.msg }

func errf(code int, format string, a ...any) error {
	return &apiError{code, fmt.Sprintf(format, a...)}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	var ae *apiError
	if errors.As(err, &ae) {
		code = ae.code
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
