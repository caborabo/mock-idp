package main

import (
	"html/template"
	"net/http"
	"strings"
)

type pageData struct {
	Title, Provider, App, Error, Info, I, LoginHint, Base, Target, Method, Decoded string
	Color                                                                          template.CSS
	TargetURL                                                                      template.URL
	Wide, OK                                                                       bool
	Users                                                                          []*User
	Sims, Scopes                                                                   []string
	Fields, Claims, Links                                                          [][2]string
	Checks                                                                         []check
	Raw                                                                            []rawBlock
}

type rawBlock struct{ Label, Body string }

var pages = template.Must(template.New("").Funcs(template.FuncMap{"join": strings.Join}).Parse(pageTemplates))

func (s *Server) page(w http.ResponseWriter, status int, name string, t *Tenant, d pageData) {
	d.Base = s.base
	d.Color = "#4f46e5"
	if t != nil {
		p := providers[t.Provider]
		if d.Provider == "" {
			d.Provider = p.Name
		}
		d.Color = template.CSS(p.Color)
		d.Sims = activeSims(t.Sims)
	}
	if d.Provider == "" {
		d.Provider = "mock-idp"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	pages.ExecuteTemplate(w, name, d)
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, t *Tenant, status int, title, msg string) {
	entry(r).fail("%s: %s", title, msg)
	s.page(w, status, "message", t, pageData{Title: title, Error: msg})
}

const pageTemplates = `
{{define "top"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · {{.Provider}}</title>
<style>
:root{--c:{{.Color}};--bg:#f4f5f7;--card:#fff;--fg:#1d2433;--mute:#667085;--line:#e3e6ec;--bad:#c62828;--ok:#1b7f3b;--warn:#a15c00}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e7eaf0;--mute:#9aa3b2;--line:#2a303b;--bad:#ff6b6b;--ok:#4cc38a;--warn:#f0b35a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:440px;margin:6vh auto;padding:0 16px}.wrap.wide{max-width:980px}
.card{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--c);border-radius:10px;padding:28px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}.dot{width:26px;height:26px;border-radius:7px;background:var(--c)}
.brand b{font-size:16px}.chip{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--mute)}
h1{font-size:20px;margin:0 0 4px}p.sub{color:var(--mute);margin:0 0 18px}
label{display:block;font-size:13px;color:var(--mute);margin:14px 0 4px}
input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:7px;background:transparent;color:inherit;font:inherit}
button,.btn{display:inline-block;padding:9px 14px;border-radius:7px;border:1px solid var(--c);background:var(--c);color:#fff;font:inherit;cursor:pointer;text-decoration:none}
button.ghost,.btn.ghost{background:transparent;color:var(--fg);border-color:var(--line)}
.full{width:100%;margin-top:16px}
.err{background:color-mix(in srgb,var(--bad) 12%,transparent);color:var(--bad);padding:10px 12px;border-radius:7px;margin-bottom:12px;word-break:break-word}
.users{display:grid;gap:6px;margin:6px 0}.users button{display:flex;justify-content:space-between;align-items:center;gap:8px;width:100%;background:transparent;color:var(--fg);border-color:var(--line);text-align:left}
.users button:hover{border-color:var(--c)}.users small{color:var(--mute)}
.tag{font-size:11px;padding:1px 6px;border-radius:4px;background:var(--line);color:var(--mute);margin-left:4px;white-space:nowrap}
.sims{margin-top:16px;font-size:12px;color:var(--warn);word-break:break-word}
.foot{text-align:center;color:var(--mute);font-size:12px;margin:16px 0}.foot a{color:inherit}
hr{border:0;border-top:1px solid var(--line);margin:20px 0}
pre{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:12px;overflow:auto;font:12px/1.5 ui-monospace,Menlo,monospace;max-height:520px;white-space:pre-wrap;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:break-word}td.k{color:var(--mute);white-space:nowrap}
.pass{color:var(--ok)}.fail{color:var(--bad)}.warn{color:var(--warn)}td.r{width:20px;font-weight:700}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}code{font:13px ui-monospace,Menlo,monospace}
</style></head><body><div class="wrap{{if .Wide}} wide{{end}}"><div class="card">
<div class="brand"><div class="dot"></div><b>{{.Provider}}</b><span class="chip">simulated</span></div>
{{end}}

{{define "bottom"}}{{if .Sims}}<div class="sims">⚠ Simulations on: {{join .Sims ", "}}</div>{{end}}</div>
<div class="foot">Not a real {{.Provider}} page · <a href="{{.Base}}/">mock-idp</a> by <a href="https://ssojet.com/?utm_source=mock-idp">SSOJet</a></div></div></body></html>{{end}}

{{define "login"}}{{template "top" .}}
<h1>Sign in</h1><p class="sub">to continue to <b>{{.App}}</b></p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post"><input type="hidden" name="i" value="{{.I}}"><input type="hidden" name="step" value="password">
<label for="u">Username</label><input id="u" name="username" value="{{.LoginHint}}" autocomplete="username" autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<button class="full">Sign in</button></form>
<hr><label>Or pick a test user (no password)</label>
<form method="post" class="users"><input type="hidden" name="i" value="{{.I}}"><input type="hidden" name="step" value="pick">
{{range .Users}}<button name="user" value="{{.ID}}"><span>{{.DisplayName}}<br><small>{{.UserName}}</small></span><span>{{if not .Active}}<span class="tag">deactivated</span>{{end}}{{if not .Email}}<span class="tag">no email</span>{{else if not .EmailVerified}}<span class="tag">unverified</span>{{end}}</span></button>
{{end}}</form>
<p class="sub" style="margin:12px 0 0">Seeded users' password is <code>password</code>.</p>
<form method="post"><input type="hidden" name="i" value="{{.I}}"><button class="ghost full" name="step" value="cancel">Cancel sign-in</button></form>
{{template "bottom" .}}{{end}}

{{define "mfa"}}{{template "top" .}}
<h1>Verify it's you</h1><p class="sub">Enter the 6-digit code from your authenticator app.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post"><input type="hidden" name="i" value="{{.I}}"><input type="hidden" name="step" value="mfa">
<label for="c">Code</label><input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus>
<button class="full">Verify</button></form>
<p class="sub" style="margin:12px 0 0">Any 6 digits pass. <code>000000</code> fails.</p>
{{template "bottom" .}}{{end}}

{{define "consent"}}{{template "top" .}}
<h1>Allow {{.App}}?</h1><p class="sub">Signed in as {{.Info}}. The app asks for:</p>
<table>{{range .Scopes}}<tr><td><code>{{.}}</code></td></tr>{{end}}</table>
<form method="post" class="row"><input type="hidden" name="i" value="{{.I}}"><input type="hidden" name="step" value="consent">
<button name="decision" value="allow">Allow</button><button class="ghost" name="decision" value="deny">Deny</button></form>
{{template "bottom" .}}{{end}}

{{define "message"}}{{template "top" .}}
<h1>{{.Title}}</h1>{{if .Error}}<div class="err">{{.Error}}</div>{{end}}{{if .Info}}<p>{{.Info}}</p>{{end}}
<div class="row"><a class="btn ghost" href="{{.Base}}/">Open the dashboard</a></div>
{{template "bottom" .}}{{end}}

{{define "autopost"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signing in…</title></head>
<body onload="document.forms[0].submit()"><form method="post" action="{{.Target}}">{{range .Fields}}<input type="hidden" name="{{index . 0}}" value="{{index . 1}}">{{end}}
<noscript><p>JavaScript is off.</p><button>Continue</button></noscript></form></body></html>{{end}}

{{define "pause"}}{{template "top" .}}
<h1>Paused before sending</h1><p class="sub"><b>Pause before send</b> is on. This is what goes to the app.</p>
<table><tr><td class="k">To</td><td>{{.Target}}</td></tr><tr><td class="k">Binding</td><td>{{.Method}}</td></tr>
{{range .Fields}}<tr><td class="k">{{index . 0}}</td><td><code>{{index . 1}}</code></td></tr>{{end}}</table>
{{if .Decoded}}<label>Decoded</label><pre>{{.Decoded}}</pre>{{end}}
{{if eq .Method "POST"}}<form method="post" action="{{.Target}}" class="row">{{range .Fields}}<input type="hidden" name="{{index . 0}}" value="{{index . 1}}">{{end}}<button>Send to app</button></form>
{{else}}<div class="row"><a class="btn" href="{{.TargetURL}}">Send to app</a></div>{{end}}
{{template "bottom" .}}{{end}}

{{define "result"}}{{template "top" .}}
<h1>{{if .OK}}<span class="pass">✓</span>{{else}}<span class="fail">✗</span>{{end}} {{.Title}}</h1><p class="sub">{{.Info}}</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
{{if .Checks}}<table>{{range .Checks}}<tr><td class="r {{.Result}}">{{if eq .Result "pass"}}✓{{else if eq .Result "warn"}}!{{else}}✗{{end}}</td><td><b>{{.Name}}</b>{{if .Detail}}<br><small>{{.Detail}}</small>{{end}}</td></tr>{{end}}</table>{{end}}
{{if .Claims}}<label>Who signed in</label><table>{{range .Claims}}<tr><td class="k">{{index . 0}}</td><td>{{index . 1}}</td></tr>{{end}}</table>{{end}}
{{range .Raw}}<label>{{.Label}}</label><pre>{{.Body}}</pre>{{end}}
<div class="row">{{range .Links}}<a class="btn ghost" href="{{index . 1}}">{{index . 0}}</a>{{end}}</div>
{{template "bottom" .}}{{end}}
`
