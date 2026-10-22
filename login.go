package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func sessionCookie(tid string) string { return "mockidp_" + tid }

// network applies the tenant's latency and outage simulations. It returns
// true when it has answered the request itself.
func (s *Server) network(w http.ResponseWriter, r *http.Request) bool {
	s.store.mu.Lock()
	var sims Simulations
	if t := s.store.tenant(r.PathValue("tenant")); t != nil {
		sims = t.Sims
	}
	s.store.mu.Unlock()
	e := entry(r)
	if d := min(sims.LatencyMs, 60000); d > 0 {
		e.note("simulated latency: %d ms", d)
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
	if c := sims.HTTPStatus; c >= 400 && c < 600 {
		e.warn("simulated outage: HTTP %d", c)
		http.Error(w, fmt.Sprintf("%d %s (simulated by mock-idp)", c, http.StatusText(c)), c)
		// An outage never lets a flow complete, so this failed request is the one shot.
		if sims.Once {
			s.store.mu.Lock()
			if t := s.store.tenant(r.PathValue("tenant")); t != nil {
				s.consumeOnce(t)
			}
			s.store.mu.Unlock()
		}
		return true
	}
	return false
}

// lookup finds the path's tenant. Callers hold store.mu.
func (s *Server) lookup(w http.ResponseWriter, r *http.Request, jsonErr bool) *Tenant {
	id := r.PathValue("tenant")
	t := s.store.tenant(id)
	if t == nil {
		if jsonErr {
			entry(r).fail("unknown tenant %q", id)
			writeJSON(w, 404, map[string]string{"error": "unknown tenant " + id})
		} else {
			s.errorPage(w, r, nil, 404, "Unknown tenant", "There is no tenant "+id+". Check the URL your app is configured with.")
		}
		return nil
	}
	entry(r).Sims = activeSims(t.Sims)
	return t
}

// beginLogin decides whether a login page is needed: auto sign-in and an
// existing session skip it; prompt=none and IsPassive forbid it.
func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request, t *Tenant, in *interaction) {
	e := entry(r)
	if ref := t.Sims.AutoLogin; ref != "" {
		if u := t.user(ref); u != nil {
			e.note("autoLogin: signed in as %s with no login page", u.UserName)
			in.UserID = u.ID
			s.complete(w, r, t, in)
			return
		}
		e.warn("autoLogin user %q does not exist; showing the login page", ref)
	}
	if !in.ForceAuthn && in.Prompt != "login" {
		if c, err := r.Cookie(sessionCookie(t.ID)); err == nil {
			if u := t.user(c.Value); u != nil && u.Active {
				e.note("existing IdP session for %s: single sign-on, no login page", u.UserName)
				in.UserID = u.ID
				s.complete(w, r, t, in)
				return
			}
		}
	}
	if in.Passive || in.Prompt == "none" {
		s.fail(w, r, t, in, "login_required", "no IdP session and the app asked for no interaction")
		return
	}
	in.ID, in.Created = randHex(12), time.Now()
	put(&s.mem, s.mem.interactions, in.ID, in)
	e.note("no session: sending the browser to the login page")
	http.Redirect(w, r, s.base+"/t/"+t.ID+"/login?i="+in.ID, http.StatusFound)
}

func (s *Server) complete(w http.ResponseWriter, r *http.Request, t *Tenant, in *interaction) {
	u := t.user(in.UserID)
	app := t.app(in.App)
	if app == nil || u == nil {
		s.errorPage(w, r, t, 400, "Sign-in interrupted", "The app or the user was deleted while you were signing in.")
		return
	}
	entry(r).Summary = fmt.Sprintf("%s signed in to %s", u.UserName, app.Name)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie(t.ID), Value: u.ID, Path: "/t/" + t.ID, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if in.Kind == "saml" {
		s.samlComplete(w, r, t, app, in, u, "")
		s.consumeOnce(t)
		return
	}
	s.oidcComplete(w, r, t, app, in, u)
	s.consumeOnce(t) // a code carries its own copy of the simulations to the token call
}

// fail ends a sign-in with an error, in the protocol the app speaks.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, t *Tenant, in *interaction, code, desc string) {
	if in.Kind == "saml" {
		entry(r).warn("SAML sign-in failed: %s (%s)", code, desc)
		if app := t.app(in.App); app != nil {
			s.samlComplete(w, r, t, app, in, nil, code)
			return
		}
	}
	s.oidcError(w, r, t, in, code, desc)
}

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	e := entry(r)
	e.Kind = "login"
	r.ParseForm()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	t := s.lookup(w, r, false)
	if t == nil {
		return
	}
	in := peek(&s.mem, s.mem.interactions, r.Form.Get("i"))
	if in == nil || in.Tenant != t.ID {
		s.errorPage(w, r, t, 400, "Sign-in expired", "This sign-in was already finished or never started. Start again from your app.")
		return
	}
	app := t.app(in.App)
	if app == nil {
		s.errorPage(w, r, t, 400, "App removed", "The app was deleted while you were signing in.")
		return
	}
	e.App = app.ID
	d := pageData{Title: "Sign in", App: app.Name, I: in.ID, Users: t.Users, LoginHint: in.LoginHint}

	if r.Method == http.MethodPost {
		switch r.Form.Get("step") {
		case "cancel":
			take(&s.mem, s.mem.interactions, in.ID)
			s.fail(w, r, t, in, "access_denied", "the user cancelled sign-in")
			return
		case "pick", "password":
			u := t.user(r.Form.Get("user"))
			if r.Form.Get("step") == "password" {
				u = t.user(r.Form.Get("username"))
				if u != nil && !t.Sims.AnyPassword && r.Form.Get("password") != u.Password {
					u = nil
				}
			}
			switch {
			case u == nil:
				d.Error = "Wrong username or password."
			case t.Sims.LockedOut:
				d.Error = "Your account is locked after too many failed attempts. (simulated)"
			case !u.Active:
				d.Error = "Your account is deactivated. Ask your administrator."
			}
			if d.Error != "" {
				e.warn("sign-in refused: %s", d.Error)
				s.page(w, 200, "login", t, d)
				return
			}
			in.UserID = u.ID
			e.note("password step passed for %s", u.UserName)
		case "mfa":
			c := r.Form.Get("code")
			if !sixDigits.MatchString(c) || c == "000000" {
				e.warn("MFA code %q refused", c)
				d.Error = "That code didn't work. Try again."
				s.page(w, 200, "mfa", t, d)
				return
			}
			in.MFADone = true
		case "consent":
			if r.Form.Get("decision") != "allow" {
				take(&s.mem, s.mem.interactions, in.ID)
				s.fail(w, r, t, in, "access_denied", "the user denied consent")
				return
			}
			in.Consented = true
		}
	}

	switch {
	case in.UserID == "":
		s.page(w, 200, "login", t, d)
	case t.Sims.RequireMFA && !in.MFADone:
		s.page(w, 200, "mfa", t, d)
	case t.Sims.ShowConsent && in.Kind == "oidc" && !in.Consented:
		d.Info = t.user(in.UserID).UserName
		d.Scopes = strings.Fields(in.Scope)
		s.page(w, 200, "consent", t, d)
	default:
		take(&s.mem, s.mem.interactions, in.ID)
		s.complete(w, r, t, in)
	}
}
