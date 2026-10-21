'use strict';
// mock-idp dashboard. No build step: plain JS against the JSON API.

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const S = { info: null, routes: [], tenants: [], t: null, ep: null, logs: [], sel: null, paused: false, lf: { q: '', kind: '', tenant: '' }, view: '', fixedTenant: '' };

// ---- html ----
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ESC[c]);
class Raw { constructor(s) { this.s = s; } }
const raw = s => new Raw(s);
const part = v => v instanceof Raw ? v.s : Array.isArray(v) ? v.map(part).join('') : (v === false || v == null) ? '' : esc(v);
const html = (str, ...vals) => raw(str.reduce((o, s, i) => o + s + (i < vals.length ? part(vals[i]) : ''), ''));
const main = h => { $('#main').innerHTML = part(h); };
const pre = t => html`<pre class="code">${t}</pre>`;
const attr = (cond, name) => cond ? raw(' ' + name) : '';

// ---- utils ----
const store = {
  get(k) { try { return localStorage.getItem('mockidp-' + k) || ''; } catch { return ''; } },
  set(k, v) { try { localStorage.setItem('mockidp-' + k, v); } catch { /* private mode */ } },
};

async function api(method, path, body) {
  const headers = { 'content-type': 'application/json' };
  const tok = store.get('token');
  if (tok) headers.authorization = 'Bearer ' + tok;
  const r = await fetch('/api' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (r.status === 401) {
    const t = prompt('This mock-idp requires its API token (MOCKIDP_API_TOKEN):');
    if (t) { store.set('token', t); return api(method, path, body); }
  }
  const text = await r.text();
  let j; try { j = JSON.parse(text); } catch { j = text; }
  if (!r.ok) throw new Error((j && j.error) || text || r.statusText);
  return j;
}

let toastTimer;
function toast(msg, bad) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = ''; }, bad ? 5000 : 2200);
}

const prov = k => S.info.providers.find(p => p.key === k) || { key: k, name: k, color: '#888', quirks: [] };
const tp = p => `/tenants/${encodeURIComponent(S.t.id)}${p}`;
const fmtTime = iso => new Date(iso).toLocaleTimeString([], { hour12: false });
function ago(iso) {
  const s = Math.round((Date.now() - new Date(iso)) / 1000);
  return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : `${Math.round(s / 3600)}h ago`;
}
const activeList = s => S.info.simulations.filter(x => s[x.key]).map(x => x.type === 'bool' ? x.label : `${x.label}: ${s[x.key]}`);
const kvc = (k, v) => html`<div class="k">${k}</div><div class="copy"><code>${v || '—'}</code>${v ? html`<button class="icon-btn" data-act="copy" data-v="${v}" title="Copy">copy</button>` : ''}</div>`;

function jwt(tok) {
  try {
    const [h, c] = tok.split('.').slice(0, 2).map(p => JSON.parse(decodeURIComponent(escape(atob(p.replace(/-/g, '+').replace(/_/g, '/'))))));
    return { header: h, claims: c };
  } catch { return null; }
}

function prettyBody(b) {
  try { return JSON.stringify(JSON.parse(b), null, 2); } catch { /* not JSON */ }
  if (/^[\w.%-]+=/.test(b) && !b.includes('\n')) return [...new URLSearchParams(b)].map(([k, v]) => `${k} = ${v}`).join('\n');
  return b;
}

// ---- data ----
async function loadTenants() { S.tenants = await api('GET', '/tenants'); renderSide(); }
async function loadTenant(id) {
  [S.t, S.ep] = await Promise.all([api('GET', `/tenants/${encodeURIComponent(id)}`), api('GET', `/tenants/${encodeURIComponent(id)}/endpoints`)]);
}
async function refreshTenant() {
  if (!S.t) return;
  const y = scrollY;
  await Promise.all([loadTenant(S.t.id), loadTenants()]);
  await route(true);
  scrollTo(0, y);
}

function renderSide() {
  $('#side-tenants').innerHTML = part(S.tenants.map(t => html`<a href="#/t/${t.id}" data-tid="${t.id}" style="--c:${prov(t.provider).color}"><span class="dot"></span>${t.name}${t.activeSimulations.length ? html`<span class="chip warn count" title="simulations on">${t.activeSimulations.length}</span>` : ''}</a>`));
  markNav();
}

function markNav() {
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  $$('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === (parts[0] === 't' ? '' : parts[0]) && parts[0] !== 't'));
  $$('[data-tid]').forEach(a => a.classList.toggle('on', parts[0] === 't' && a.dataset.tid === parts[1]));
}

// ---- router ----
async function route(cached) {
  const parts = location.hash.replace(/^#\/?/, '').split('/').map(decodeURIComponent);
  S.view = parts[0] || '';
  markNav();
  try {
    if (parts[0] === 't') await tenantPage(parts[1], parts[2] || 'overview', cached === true);
    else if (parts[0] === 'logs') logsPage(parts[1]);
    else if (parts[0] === 'decoder') decoderPage();
    else if (parts[0] === 'api') apiPage();
    else homePage();
  } catch (e) {
    main(html`<div class="card err">${e.message}</div>`);
  }
}
window.addEventListener('hashchange', () => route());

// ---- home ----
function homePage() {
  main(html`
  <div class="head"><div class="grow"><h1>Simulated identity providers</h1>
    <p class="muted" style="margin-top:4px">Each tenant behaves like a real Okta, Entra ID, Google Workspace… org over SAML, OIDC and SCIM, quirks included. Point your app at one, then break it on purpose from <b>Simulations</b>.</p></div>
    <div class="row"><button class="btn" data-act="reset-all">Reset demo data</button><button class="btn primary" data-act="new-tenant">New tenant</button></div></div>
  <div class="grid">${S.tenants.map(t => {
    const p = prov(t.provider), n = t.activeSimulations.length;
    return html`<a class="card tcard" href="#/t/${t.id}" style="--c:${p.color}">
      <div class="row"><span class="name grow">${t.name}</span>${n ? html`<span class="chip warn">${n} simulation${n > 1 ? 's' : ''} on</span>` : ''}</div>
      <div class="muted small">${p.name} · ${t.domain}</div>
      <div class="stats"><span>${t.users} users</span><span>${t.groups} groups</span><span>${t.apps} apps</span><span>${t.scimTargets} SCIM</span></div></a>`;
  })}<button class="card tcard new" data-act="new-tenant">+ New tenant</button></div>
  <h3>Start in a minute</h3>
  <div class="card"><ol style="margin:0;padding-left:18px;line-height:1.9">
    <li>Open a tenant and press <b>Test SAML login</b> or <b>Test OIDC login</b>. The built-in test app signs in through the real flow and shows every check it ran.</li>
    <li>Turn on a simulation (expired assertion, wrong audience, alg=none…) and sign in again. Watch it fail in <a href="#/logs">Live logs</a>.</li>
    <li>Register your own app under <b>Apps</b>, and copy the endpoints from <b>Overview</b>.</li>
    <li>Point <b>SCIM</b> at your app's SCIM server and run the conformance suite as Okta or as Entra.</li>
    <li>Let an AI agent drive all of it: <a href="#/api">API &amp; MCP</a>.</li></ol></div>`);
}

// ---- tenant ----
const TABS = [['overview', 'Overview'], ['users', 'Users'], ['groups', 'Groups'], ['apps', 'Apps'], ['scim', 'SCIM'], ['simulations', 'Simulations'], ['logs', 'Logs']];

async function tenantPage(id, tab, cached) {
  if (!cached || !S.t || S.t.id !== id) await loadTenant(id);
  const t = S.t, p = prov(t.provider), active = activeList(t.simulations);
  const counts = { users: t.users.length, groups: t.groups.length, apps: t.apps.length, scim: t.scimTargets.length, simulations: active.length || null };
  const samlApp = S.ep.apps.find(a => a.type === 'saml' && a.testLogin), oidcApp = S.ep.apps.find(a => a.type === 'oidc' && a.testLogin);
  main(html`
  <div class="head"><div class="grow">
      <div class="row"><span class="dot" style="--c:${p.color};width:12px;height:12px"></span><h1>${t.name}</h1><span class="chip prov">${p.name}</span></div>
      <div class="muted small" style="margin-top:4px">${t.domain} · tenant <code>${t.id}</code> · external id <code>${t.externalId}</code></div></div>
    <div class="row">${samlApp ? html`<a class="btn" href="${samlApp.testLogin}" target="_blank" rel="noopener">Test SAML login ↗</a>` : ''}${oidcApp ? html`<a class="btn" href="${oidcApp.testLogin}" target="_blank" rel="noopener">Test OIDC login ↗</a>` : ''}</div></div>
  ${active.length ? html`<div class="banner"><b>Simulations on</b><span class="chips">${active.map(a => html`<span class="chip warn">${a}</span>`)}</span><button class="btn sm" data-act="sims-reset">Turn all off</button></div>` : ''}
  <div class="tabs">${TABS.map(([k, l]) => html`<a href="#/t/${t.id}/${k}" class="${k === tab ? 'on' : ''}">${l}${counts[k] != null ? html`<span class="n">${counts[k]}</span>` : ''}</a>`)}</div>
  <div id="tab"></div>`);
  S.fixedTenant = tab === 'logs' ? t.id : '';
  const fn = { overview: overviewTab, users: usersTab, groups: groupsTab, apps: appsTab, scim: scimTab, simulations: simsTab, logs: () => logsShell(true) }[tab] || overviewTab;
  $('#tab').innerHTML = part(fn(t));
  if (tab === 'logs') { drawLogList(); drawDetail(); }
}

function overviewTab(t) {
  const p = prov(t.provider), ep = S.ep;
  return html`<div class="split">
  <div class="stack">
    <div class="card"><h2>OpenID Connect</h2><div class="kv">${kvc('Issuer', ep.oidc.issuer)}${kvc('Discovery', ep.oidc.discovery)}${kvc('Authorize', ep.oidc.authorize)}${kvc('Token', ep.oidc.token)}${kvc('Userinfo', ep.oidc.userinfo)}${kvc('JWKS', ep.oidc.jwks)}${kvc('Logout', ep.oidc.logout)}</div></div>
    <div class="card"><h2>Signing certificate</h2><div class="kv">${kvc('SHA-256', ep.certificateSha256)}${kvc('SHA-1', ep.certificateSha1)}${kvc('kid', ep.kid)}</div>
      <div class="row" style="margin-top:12px"><a class="btn sm" href="${ep.certificateUrl}">Download PEM</a><button class="btn sm" data-act="copy" data-v="${ep.certificatePem}">Copy PEM</button><button class="btn sm danger" data-act="rotate">Rotate key</button></div>
      <p class="small muted" style="margin:8px 0 0">Rotating breaks apps that pinned the old certificate or cached the JWKS, as a real rotation does.</p></div>
    <div class="card"><h2>Built-in test SP certificate</h2>
      <p class="small muted" style="margin:0 0 10px">The test SP signs its AuthnRequests and decrypts assertions with this. Paste it into an app's encryption or signing certificate to try those features with the test SP.</p>
      <button class="btn sm" data-act="copy" data-v="${S.spCert}">Copy PEM</button></div>
  </div>
  <div class="stack">
    <div class="card"><h2>How ${p.name} differs</h2><ul style="margin:0;padding-left:18px;line-height:1.7">${p.quirks.map(q => html`<li>${q}</li>`)}</ul></div>
    <div class="card"><h2>Apps</h2>${ep.apps.map(a => html`<div style="margin-bottom:14px"><div class="row"><b>${a.name}</b><span class="chip">${a.type.toUpperCase()}</span></div>
      <div class="kv small" style="margin-top:6px">${a.type === 'saml' ? [kvc('Metadata URL', a.metadataUrl), kvc('SSO URL', a.ssoUrl), kvc('IdP entity ID', a.idpEntityId)] : [kvc('Client ID', a.clientId), a.clientSecret ? kvc('Client secret', a.clientSecret) : '']}</div></div>`)}
      <a href="#/t/${t.id}/apps" class="small">Manage apps →</a></div>
    <div class="card"><h2>Danger zone</h2><button class="btn danger" data-act="delete-tenant">Delete tenant</button></div>
  </div></div>`;
}

function usersTab(t) {
  const groupsOf = id => t.groups.filter(g => g.members.includes(id)).map(g => g.name).join(', ');
  const auto = t.simulations.autoLogin;
  return html`<div class="row" style="margin-bottom:12px"><span class="muted small grow">The seed includes a deactivated user, an unverified or missing email, a guest from another domain and non-ASCII names. Password: <code>password</code>.</span>
    <button class="btn" data-act="gen-users">Generate 25</button><button class="btn primary" data-act="user-new">Add user</button></div>
  <div class="scroll"><table class="t"><thead><tr><th>User</th><th>ID</th><th>Email</th><th>Groups</th><th>Status</th><th></th></tr></thead><tbody>
  ${t.users.map(u => html`<tr><td><b>${u.displayName}</b><div class="small muted">${u.userName}</div></td><td><code class="small">${u.id}</code></td>
    <td>${u.email || html`<span class="chip bad">no email</span>`} ${u.email && !u.emailVerified ? html`<span class="chip warn">unverified</span>` : ''}</td>
    <td class="small">${groupsOf(u.id)}</td><td>${u.active ? html`<span class="chip ok">active</span>` : html`<span class="chip bad">deactivated</span>`}</td>
    <td class="actions"><button class="icon-btn" data-act="autologin" data-id="${u.userName}" title="Skip the login page and sign in as this user">${auto === u.userName ? '✓ auto sign-in' : 'auto sign-in'}</button>
      <button class="icon-btn" data-act="user-edit" data-id="${u.id}">edit</button><button class="icon-btn" data-act="user-del" data-id="${u.id}">delete</button></td></tr>`)}
  </tbody></table></div>`;
}

function groupsTab(t) {
  const name = id => (t.users.find(u => u.id === id) || {}).displayName || id;
  return html`<div class="row" style="margin-bottom:12px"><span class="grow muted small">Groups reach apps as SAML attributes, the groups claim and SCIM group pushes.</span><button class="btn primary" data-act="group-new">Add group</button></div>
  <div class="scroll"><table class="t"><thead><tr><th>Group</th><th>ID</th><th>Members</th><th></th></tr></thead><tbody>
  ${t.groups.map(g => html`<tr><td><b>${g.name}</b></td><td><code class="small">${g.id}</code></td><td class="small">${g.members.length}: ${g.members.map(name).join(', ')}</td>
    <td class="actions"><button class="icon-btn" data-act="group-edit" data-id="${g.id}">edit</button><button class="icon-btn" data-act="group-del" data-id="${g.id}">delete</button></td></tr>`)}
  </tbody></table></div>`;
}

function appsTab(t) {
  return html`<div class="row" style="margin-bottom:12px"><span class="grow muted small">The built-in test apps sign in through the real flow and show every check a careful app runs.</span>
    <button class="btn" data-act="app-new" data-type="saml">Add SAML app</button><button class="btn primary" data-act="app-new" data-type="oidc">Add OIDC app</button></div>
  <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(min(380px,100%),1fr))">${t.apps.map(a => {
    const e = S.ep.apps.find(x => x.id === a.id) || {};
    const signed = [a.signResponse && 'response', a.signAssertion && 'assertion'].filter(Boolean).join(' + ') || 'nothing';
    return html`<div class="card"><div class="row"><b class="grow">${a.name}</b><span class="chip">${a.type.toUpperCase()}</span></div>
      <div class="kv small" style="margin:10px 0">${a.type === 'saml'
        ? [kvc('SP entity ID', a.entityId), kvc('ACS URL', a.acsUrl), kvc('Metadata', e.metadataUrl), kvc('NameID', `${(a.nameIdFormat || '').split(':').pop()} ← ${a.nameIdSource}`), kvc('Signed', signed),
           kvc('Encrypted', a.encryptAssertion ? `${a.encryptionAlg} + ${a.keyTransportAlg}` : 'no'),
           kvc('Signed requests', a.requireSignedRequests ? 'required' : a.spSigningCert ? 'verified when signed' : 'not checked')]
        : [kvc('Client ID', a.clientId), a.public ? kvc('Client', 'public (no secret)') : kvc('Secret', a.clientSecret), kvc('Redirect URIs', (a.redirectUris || []).join(', ')), kvc('PKCE', a.requirePkce ? 'required' : 'optional')]}</div>
      <div class="row">${e.testLogin ? html`<a class="btn sm primary" href="${e.testLogin}" target="_blank" rel="noopener">Test login ↗</a>` : ''}
        ${a.type === 'saml' && e.testLogin && e.testLogin.includes('/sp/saml/') && a.spSigningCert ? html`<a class="btn sm" href="${e.testLogin}?sign=0" target="_blank" rel="noopener" title="The test SP sends its AuthnRequest unsigned">Unsigned request ↗</a><a class="btn sm" href="${e.testLogin}?tamper=1" target="_blank" rel="noopener" title="The test SP breaks its request signature">Tampered request ↗</a>` : ''}
        ${a.type === 'oidc' ? html`<button class="btn sm" data-act="mint" data-id="${a.id}">Mint tokens</button>` : html`<button class="btn sm" data-act="mk-saml" data-id="${a.id}">Make SAMLResponse</button><a class="btn sm" href="${e.metadataUrl}?download">Metadata ↓</a>`}
        <button class="btn sm" data-act="app-edit" data-id="${a.id}">Edit</button><button class="btn sm danger" data-act="app-del" data-id="${a.id}">Delete</button></div></div>`;
  })}</div>`;
}

const SCIM_FLAVORS = ['okta', 'entra', 'onelogin', 'jumpcloud', 'generic'];

function runTable(r) {
  return html`<h3>Last run: ${r.kind} as ${prov(r.flavor).name} · ${ago(r.time)} · <span style="color:var(--ok)">${r.passed} passed</span>, <span style="color:var(--bad)">${r.failed} failed</span>, ${r.warned} warnings</h3>
  <table class="t checks"><tbody>${r.checks.map(c => html`<tr><td class="r ${c.result}">${c.result === 'pass' ? '✓' : c.result === 'warn' ? '!' : '✗'}</td><td><b>${c.name}</b><div class="small muted">${c.detail}</div></td>
    <td class="actions">${c.log ? html`<a class="small" href="#/logs/${c.log}">request →</a>` : ''}</td></tr>`)}</tbody></table>`;
}

function scimTab(t) {
  return html`<div class="card" style="margin-bottom:12px"><p style="margin:0">Here the IdP is the SCIM <b>client</b>, as Okta and Entra provisioning are. Add your app's SCIM base URL and token.
    <b>Auto-push</b> provisions on every user and group change. <b>Conformance</b> sends a throwaway user and group through the calls that provider really makes.</p></div>
  <div class="row" style="margin-bottom:12px"><span class="grow"></span><button class="btn primary" data-act="target-new">Add SCIM target</button></div>
  ${t.scimTargets.length === 0 ? html`<div class="card empty">No SCIM targets yet. Add your app's SCIM endpoint, e.g. <code>http://localhost:3000/scim/v2</code>.</div>` : t.scimTargets.map(g => html`<div class="card" style="margin-bottom:12px">
    <div class="row"><b class="grow">${g.name}</b><span class="chip">${prov(g.flavor || t.provider).name} flavor</span><span class="chip ${g.autoPush ? 'ok' : ''}">auto-push ${g.autoPush ? 'on' : 'off'}</span></div>
    <div class="kv small" style="margin:10px 0">${kvc('Base URL', g.baseUrl)}<div class="k">Token</div><div>${g.token ? '••••' + g.token.slice(-4) : '(none)'}</div><div class="k">Mapped</div><div>${Object.keys(g.userMap || {}).length} users, ${Object.keys(g.groupMap || {}).length} groups</div></div>
    <div class="row"><button class="btn sm" data-act="scim" data-k="test" data-id="${g.id}">Test connection</button><button class="btn sm" data-act="scim" data-k="sync" data-id="${g.id}">Full sync</button><button class="btn sm" data-act="scim-push" data-id="${g.id}">Push one…</button>
      <span class="row" style="gap:4px"><select id="flv-${g.id}" aria-label="Conformance flavor">${S.info.providers.filter(p => SCIM_FLAVORS.includes(p.key)).map(p => html`<option value="${p.key}"${attr((g.flavor || t.provider) === p.key, 'selected')}>${p.name}</option>`)}</select><button class="btn sm primary" data-act="scim" data-k="conformance" data-id="${g.id}">Run conformance</button></span>
      <span class="grow"></span><button class="btn sm" data-act="target-edit" data-id="${g.id}">Edit</button><button class="btn sm danger" data-act="target-del" data-id="${g.id}">Delete</button></div>
    ${g.lastResult ? runTable(g.lastResult) : ''}</div>`)}`;
}

function simControl(x, v, t) {
  let ctl;
  if (x.type === 'bool') ctl = html`<label class="switch"><input type="checkbox" data-sim="${x.key}"${attr(v, 'checked')} aria-label="${x.label}"><span></span></label>`;
  else if (x.type === 'int') ctl = html`<input type="number" data-sim="${x.key}" value="${v || 0}" aria-label="${x.label}">`;
  else if (x.type === 'user') ctl = html`<select data-sim="${x.key}" aria-label="${x.label}"><option value="">off</option>${t.users.map(u => html`<option value="${u.userName}"${attr(v === u.userName, 'selected')}>${u.userName}</option>`)}</select>`;
  else ctl = html`<select data-sim="${x.key}" aria-label="${x.label}"><option value="">off</option>${(x.options || []).map(o => html`<option${attr(v === o, 'selected')}>${o}</option>`)}</select>`;
  return html`<div class="sim ${v ? 'on' : ''}">${x.type === 'bool' ? ctl : ''}<div class="txt"><div class="lbl">${x.label}</div>${x.desc ? html`<div class="desc">${x.desc}</div>` : ''}</div>${x.type !== 'bool' ? ctl : ''}</div>`;
}

function simsTab(t) {
  const groups = {};
  S.info.simulations.forEach(x => (groups[x.group] ||= []).push(x));
  return html`<div class="row" style="margin-bottom:12px"><span class="small muted grow">Changes apply at once to every app of this tenant. Turn on <b>One shot</b> to clear them after the next sign-in.</span><button class="btn" data-act="sims-reset">Turn all off</button></div>
  <h3 style="margin-top:0">Presets</h3><div class="row" style="margin-bottom:16px">${S.info.presets.map(p => html`<button class="btn sm" data-act="preset" data-k="${p.key}">${p.label}</button>`)}</div>
  <div class="sim-groups">${Object.entries(groups).map(([g, list]) => html`<div class="card"><h2>${g}</h2>${list.map(x => simControl(x, t.simulations[x.key], t))}</div>`)}</div>`;
}

// ---- logs ----
function logsShell(fixed) {
  return html`<div class="row" style="margin-bottom:10px">
    <input type="text" id="lq" placeholder="Search URLs, bodies, notes…" value="${S.lf.q}" style="flex:1;min-width:180px" aria-label="Search logs">
    <select id="lkind" aria-label="Kind">${['', 'oidc', 'saml', 'scim', 'sp', 'login', 'api'].map(k => html`<option value="${k}"${attr(S.lf.kind === k, 'selected')}>${k || 'all kinds'}</option>`)}</select>
    ${fixed ? '' : html`<select id="ltenant" aria-label="Tenant"><option value="">all tenants</option>${S.tenants.map(t => html`<option value="${t.id}"${attr(S.lf.tenant === t.id, 'selected')}>${t.name}</option>`)}</select>`}
    <button class="btn" data-act="pause">${S.paused ? 'Resume' : 'Pause'}</button><button class="btn" data-act="export-logs">Export</button><button class="btn danger" data-act="clear-logs">Clear</button></div>
  <div class="logs"><div class="loglist" id="loglist"></div><div class="logdetail" id="logdetail"></div></div>`;
}

function logsPage(id) {
  S.fixedTenant = '';
  if (id) S.sel = +id;
  main(html`<div class="head"><div class="grow"><h1>Live logs</h1><p class="muted" style="margin-top:4px">Every exchange with the IdP, the test apps and your SCIM server: raw request and response, decoded SAML and JWTs, and notes on what the IdP decided.</p></div></div>${logsShell(false)}`);
  drawLogList();
  drawDetail();
}

function matches(e) {
  const q = S.lf.q.toLowerCase(), tn = S.fixedTenant || S.lf.tenant;
  return (!tn || e.tenant === tn) && (!S.lf.kind || e.kind.startsWith(S.lf.kind)) &&
    (!q || `${e.summary} ${e.url} ${e.reqBody || ''} ${e.respBody || ''} ${(e.notes || []).join(' ')}`.toLowerCase().includes(q));
}

function logRow(e) {
  return html`<div class="logrow ${e.level} ${S.sel === e.id ? 'sel' : ''}" data-act="sel-log" data-id="${e.id}">
    <span class="time">${fmtTime(e.time)}</span><span class="sum" title="${e.summary}">${e.summary}<div class="kind">${e.kind}${e.tenant ? ' · ' + e.tenant : ''}</div></span>
    <span class="status ${e.status >= 400 ? 'e' : 'o'}">${e.status || ''}</span></div>`;
}

function drawLogList() {
  const el = $('#loglist');
  if (!el) return;
  const list = S.logs.filter(matches).slice(-500).reverse();
  el.innerHTML = list.length ? part(list.map(logRow)) : part(html`<div class="empty" id="logempty">No traffic yet. Sign in through a test app and it shows up here.</div>`);
}

function headersTable(h) {
  if (!h) return '';
  return html`<table class="t small" style="margin-bottom:8px"><tbody>${Object.entries(h).map(([k, v]) => html`<tr><td class="k">${k}</td><td><code style="overflow-wrap:anywhere">${v.join(', ')}</code></td></tr>`)}</tbody></table>`;
}

async function drawDetail() {
  const el = $('#logdetail');
  if (!el) return;
  let e = S.logs.find(x => x.id === S.sel);
  if (!e && S.sel) { try { e = await api('GET', '/logs/' + S.sel); } catch { /* aged out */ } }
  if (!e) { el.innerHTML = part(html`<div class="empty">Pick an entry on the left.</div>`); return; }
  const noteCls = n => n.startsWith('⚠') ? 'w' : n.startsWith('✗') ? 'x' : '';
  el.innerHTML = part(html`
    <div class="row"><span class="method ${e.method}">${e.method}</span><code class="grow" style="overflow-wrap:anywhere">${e.url}</code></div>
    <div class="row small muted" style="margin:6px 0 12px"><span class="status ${e.status >= 400 ? 'e' : 'o'}">${e.status}</span><span>${e.durationMs} ms</span><span>${new Date(e.time).toLocaleString()}</span><span>${e.kind}</span>${e.tenant ? html`<a href="#/t/${e.tenant}">${e.tenant}</a>` : ''}<span>#${e.id}</span></div>
    <h2>${e.summary}</h2>
    ${e.sims && e.sims.length ? html`<div class="row" style="margin-bottom:8px">${e.sims.map(s => html`<span class="chip warn">${s}</span>`)}</div>` : ''}
    ${e.notes && e.notes.length ? html`<ul class="notes">${e.notes.map(n => html`<li class="${noteCls(n)}">${n}</li>`)}</ul>` : ''}
    ${(e.decoded || []).map((d, i) => html`<details${attr(i < 3, 'open')}><summary>${d.label}</summary><div>${pre(d.kind === 'xml' ? d.value : JSON.stringify(d.value, null, 2))}</div></details>`)}
    <details><summary>Request</summary><div>${headersTable(e.reqHeaders)}${e.reqBody ? pre(prettyBody(e.reqBody)) : ''}</div></details>
    <details><summary>Response</summary><div>${headersTable(e.respHeaders)}${e.respBody ? pre(prettyBody(e.respBody)) : ''}</div></details>
    <div class="row" style="margin-top:12px"><button class="btn sm" data-act="copy-curl" data-id="${e.id}">Copy as curl</button><button class="btn sm" data-act="copy-json" data-id="${e.id}">Copy entry as JSON</button></div>`);
}

function curlOf(e) {
  const skip = /^(host|content-length|accept-encoding|connection|cookie|upgrade-insecure-requests|sec-.*)$/i;
  const q = s => `'${String(s).replace(/'/g, `'\\''`)}'`;
  const parts = [`curl -X ${e.method} ${q(e.url)}`];
  for (const [k, v] of Object.entries(e.reqHeaders || {})) if (!skip.test(k)) parts.push(`-H ${q(k + ': ' + v.join(', '))}`);
  if (e.reqBody) parts.push(`--data-raw ${q(e.reqBody)}`);
  return parts.join(' \\\n  ');
}

// ---- decoder ----
function decoderPage() {
  main(html`<div class="head"><div class="grow"><h1>Decoder</h1><p class="muted" style="margin-top:4px">Paste a JWT, a SAMLRequest or SAMLResponse (base64, deflated or not), raw XML, or a whole callback URL.</p></div></div>
  <div class="card"><textarea id="dec-in" rows="7" placeholder="eyJhbGciOi…   or   PHNhbWxwOlJlc3BvbnNl…   or   https://app.example.com/callback?code=…" aria-label="Input"></textarea>
  <div class="row" style="margin-top:8px"><button class="btn primary" data-act="decode">Decode</button></div></div><div id="dec-out" style="margin-top:12px"></div>`);
}

function decodedView(r) {
  if (r.type === 'jwt') return html`<div class="card stack"><h2>JWT</h2><b class="small">Header</b>${pre(JSON.stringify(r.header, null, 2))}<b class="small">Claims</b>${pre(JSON.stringify(r.claims, null, 2))}${Object.keys(r.times || {}).length ? html`<b class="small">Times</b>${pre(JSON.stringify(r.times, null, 2))}` : ''}</div>`;
  if (r.xml) return html`<div class="card"><h2>${r.type === 'saml' ? 'SAML message' : 'XML'}</h2>${pre(r.xml)}</div>`;
  if (r.type === 'url') {
    const nested = Object.entries(r).filter(([k]) => !['type', 'params'].includes(k));
    return html`<div class="card"><h2>URL parameters</h2><table class="t small"><tbody>${Object.entries(r.params).map(([k, v]) => html`<tr><td class="k">${k}</td><td><code style="overflow-wrap:anywhere">${v}</code></td></tr>`)}</tbody></table></div>
      ${nested.map(([k, v]) => html`<h3>${k}</h3>${decodedView(v)}`)}`;
  }
  return html`<div class="card err">${r.error || 'Could not decode that.'}</div>`;
}

// ---- API page ----
function apiPage() {
  const base = S.info.baseUrl;
  main(html`<div class="head"><div class="grow"><h1>API &amp; MCP</h1><p class="muted" style="margin-top:4px">Everything in this dashboard is an API call. AI agents get the same control over MCP, where every route is a tool.</p></div></div>
  <div class="split"><div class="card stack"><h2>Connect an agent (MCP)</h2>
      <div><div class="small muted">Claude Code</div>${pre(`claude mcp add --transport http mock-idp ${base}/mcp`)}</div>
      <div><div class="small muted">Any MCP client (streamable HTTP)</div>${pre(JSON.stringify({ mcpServers: { 'mock-idp': { type: 'http', url: base + '/mcp' } } }, null, 2))}</div>
      <div class="small muted">Plain-text docs for LLMs: <a href="/llms.txt" target="_blank">/llms.txt</a></div></div>
    <div class="card stack"><h2>Try it</h2>${pre(`curl ${base}/api/tenants\n\ncurl -X PATCH ${base}/api/tenants/okta/simulations \\\n  -H 'content-type: application/json' \\\n  -d '{"samlExpired": true, "once": true}'\n\ncurl '${base}/api/logs?tenant=okta&kind=saml'`)}
      <div class="small muted">Set <code>MOCKIDP_API_TOKEN</code> to require <code>Authorization: Bearer …</code> on the API and MCP.</div></div></div>
  <h3>Routes (${S.routes.length})</h3><div class="scroll"><table class="t"><thead><tr><th>Route</th><th>MCP tool</th><th>What it does</th></tr></thead><tbody>
  ${S.routes.map(r => html`<tr><td style="white-space:nowrap"><span class="method ${r.method}">${r.method}</span> <code>${r.path}</code></td><td><code>${r.name}</code></td>
    <td class="small">${r.description}${r.exampleBody ? html`<div style="margin-top:3px"><code class="muted">${JSON.stringify(r.exampleBody)}</code></div>` : ''}</td></tr>`)}</tbody></table></div>`);
}

// ---- dialogs ----
const dlg = () => $('#dlg');

function field(f, v) {
  const val = v[f.k], id = 'f-' + f.k;
  const hint = f.hint ? html`<div class="hint">${f.hint}</div>` : '';
  let input;
  switch (f.type) {
    case 'bool':
      return html`<div class="field check" data-field="${f.k}"><input type="checkbox" id="${id}" name="${f.k}"${attr(val, 'checked')}><label for="${id}">${f.label}</label></div>`;
    case 'select':
      input = html`<select id="${id}" name="${f.k}">${f.options.map(o => { const [ov, ol] = Array.isArray(o) ? o : [o, o]; return html`<option value="${ov}"${attr(String(val ?? '') === String(ov), 'selected')}>${ol}</option>`; })}</select>`;
      break;
    case 'lines': input = html`<textarea id="${id}" name="${f.k}" rows="3">${(val || []).join('\n')}</textarea>`; break;
    case 'textarea': input = html`<textarea id="${id}" name="${f.k}" rows="5" placeholder="${f.placeholder || ''}">${val || ''}</textarea>`; break;
    case 'kv': input = html`<textarea id="${id}" name="${f.k}" rows="3">${Object.entries(val || {}).map(([k, x]) => `${k}=${x}`).join('\n')}</textarea>`; break;
    case 'attrs': input = html`<textarea id="${id}" name="${f.k}" rows="6">${(val || []).map(a => `${a.name} = ${a.field}`).join('\n')}</textarea>`; break;
    case 'members':
      input = html`<div class="members">${f.options.map(([ov, ol]) => html`<label><input type="checkbox" name="${f.k}" value="${ov}"${attr((val || []).includes(ov), 'checked')}>${ol}</label>`)}</div>`;
      break;
    default:
      input = html`<input type="${f.type || 'text'}" id="${id}" name="${f.k}" value="${val ?? ''}" placeholder="${f.placeholder || ''}" autocomplete="off">`;
  }
  return html`<div class="field" data-field="${f.k}"><label for="${id}">${f.label}</label>${input}${hint}</div>`;
}

function collect(form, fields) {
  const out = {};
  for (const f of fields) {
    if (f.type === 'members') { out[f.k] = $$(`input[name="${f.k}"]:checked`, form).map(i => i.value); continue; }
    const el = form.elements[f.k];
    if (!el) continue;
    const lines = () => el.value.split('\n').map(s => s.trim()).filter(Boolean);
    if (f.type === 'bool') out[f.k] = el.checked;
    else if (f.type === 'lines') out[f.k] = lines();
    else if (f.type === 'kv') out[f.k] = Object.fromEntries(lines().filter(l => l.includes('=')).map(l => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()]));
    else if (f.type === 'attrs') out[f.k] = lines().filter(l => l.includes('=')).map(l => ({ name: l.slice(0, l.lastIndexOf('=')).trim(), field: l.slice(l.lastIndexOf('=') + 1).trim() }));
    else if (f.type === 'number') out[f.k] = parseInt(el.value || '0', 10) || 0;
    else out[f.k] = el.value;
  }
  return out;
}

// form opens a dialog; submit may return a function to run after it closes.
function form({ title, fields, values = {}, submit, wide, okLabel = 'Save' }) {
  const d = dlg();
  d.className = wide ? 'wide' : '';
  d.innerHTML = part(html`<form><div class="dh"><h2 class="grow" style="margin:0">${title}</h2><button type="button" class="icon-btn" data-close aria-label="Close">✕</button></div>
    <div class="db">${fields.map(f => field(f, values))}<div class="err" id="ferr"></div></div>
    <div class="df"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary">${okLabel}</button></div></form>`);
  const f = $('form', d);
  const sync = () => { const v = collect(f, fields); fields.forEach(fd => { if (fd.when) $(`[data-field="${fd.k}"]`, f).hidden = !fd.when(v); }); };
  f.addEventListener('change', sync);
  sync();
  $$('[data-close]', d).forEach(b => { b.onclick = () => d.close(); });
  f.onsubmit = async ev => {
    ev.preventDefault();
    const btn = $('.btn.primary', f);
    btn.disabled = true;
    try {
      const next = await submit(collect(f, fields));
      d.close();
      if (typeof next === 'function') next();
    } catch (e) { $('#ferr', f).textContent = e.message; } finally { btn.disabled = false; }
  };
  d.showModal();
}

function showResult(title, sections) {
  const d = dlg();
  d.className = 'wide';
  d.innerHTML = part(html`<form method="dialog"><div class="dh"><h2 class="grow" style="margin:0">${title}</h2><button class="icon-btn" aria-label="Close">✕</button></div>
    <div class="db">${sections.map(([l, t]) => html`<div><div class="row" style="margin-bottom:4px"><b class="grow small">${l}</b><button type="button" class="icon-btn" data-act="copy" data-v="${t}">copy</button></div>${pre(t)}</div>`)}</div>
    <div class="df"><button class="btn">Close</button></div></form>`);
  d.showModal();
}

const userOptions = () => S.t.users.map(u => [u.userName, `${u.displayName} — ${u.userName}`]);

function userForm(u) {
  const t = S.t;
  form({
    title: u ? 'Edit ' + u.userName : 'Add user',
    values: u ? { ...u, groups: t.groups.filter(g => g.members.includes(u.id)).map(g => g.id) } : { active: true, emailVerified: true, password: 'password' },
    fields: [
      { k: 'userName', label: 'Username', hint: 'Usually the email, or the UPN on Entra and AD FS.' }, { k: 'email', label: 'Email', hint: 'Leave empty to test apps that assume every user has one.' },
      { k: 'givenName', label: 'First name' }, { k: 'familyName', label: 'Last name' }, { k: 'displayName', label: 'Display name' }, { k: 'password', label: 'Password' },
      { k: 'active', label: 'Active', type: 'bool' }, { k: 'emailVerified', label: 'Email verified', type: 'bool' },
      { k: 'title', label: 'Job title' }, { k: 'department', label: 'Department' }, { k: 'phone', label: 'Phone' }, { k: 'employeeNumber', label: 'Employee number' },
      { k: 'attributes', label: 'Custom attributes', type: 'kv', hint: 'One per line, name=value. Map them in SAML as attr.name. roles=admin,editor becomes a roles claim on Entra and Keycloak.' },
      { k: 'groups', label: 'Groups', type: 'members', options: t.groups.map(g => [g.id, g.name]) },
    ],
    submit: async v => {
      if (u) await api('PATCH', tp('/users/' + encodeURIComponent(u.id)), v);
      else await api('POST', tp('/users'), v);
      toast('Saved');
      await refreshTenant();
    },
  });
}

function groupForm(g) {
  form({
    title: g ? 'Edit ' + g.name : 'Add group',
    values: g || {},
    fields: [{ k: 'name', label: 'Name' }, { k: 'members', label: 'Members', type: 'members', options: S.t.users.map(u => [u.id, u.displayName]) }],
    submit: async v => {
      if (g) await api('PATCH', tp('/groups/' + encodeURIComponent(g.id)), v);
      else await api('POST', tp('/groups'), v);
      await refreshTenant();
    },
  });
}

function appForm(a) {
  const isNew = !a.id, p = prov(S.t.provider);
  const saml = v => v.type === 'saml', oidc = v => v.type === 'oidc';
  form({
    title: isNew ? `Add ${a.type.toUpperCase()} app` : 'Edit ' + a.name, wide: true, values: a, okLabel: isNew ? 'Create' : 'Save',
    fields: [
      { k: 'name', label: 'Name', placeholder: 'My app' },
      { k: 'type', label: 'Protocol', type: 'select', options: [['saml', 'SAML 2.0'], ['oidc', 'OpenID Connect']] },
      { k: 'entityId', label: 'SP entity ID (audience)', when: saml, placeholder: 'https://app.example.com/saml/metadata' },
      { k: 'acsUrl', label: 'ACS URL', when: saml, placeholder: 'http://localhost:3000/saml/acs' },
      { k: 'sloUrl', label: 'Single logout URL (optional)', when: saml },
      { k: 'nameIdFormat', label: 'NameID format', type: 'select', options: S.info.nameIdFormats, when: saml },
      { k: 'nameIdSource', label: 'NameID value', type: 'select', options: [['email', 'email'], ['username', 'username'], ['id', 'user id'], ['persistent', 'persistent (pairwise per app)']], when: saml },
      { k: 'signResponse', label: 'Sign the Response', type: 'bool', when: saml },
      { k: 'signAssertion', label: 'Sign the Assertion', type: 'bool', when: saml },
      { k: 'sigAlg', label: 'Signature algorithm', type: 'select', options: [['sha256', 'RSA-SHA256'], ['sha1', 'RSA-SHA1 (legacy)']], when: saml },
      { k: 'attributes', label: 'Attributes', type: 'attrs', when: saml, hint: `One per line: AttributeName = field. Fields: ${S.info.attributeFields.join(', ')}.${isNew ? ` Leave empty for ${p.name}'s defaults.` : ''}` },
      { k: 'attrNameFormat', label: 'Attribute NameFormat', type: 'select', options: [['', '(omit)'], ['urn:oasis:names:tc:SAML:2.0:attrname-format:basic', 'basic'], ['urn:oasis:names:tc:SAML:2.0:attrname-format:uri', 'uri'], ['urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified', 'unspecified']], when: saml },
      { k: 'issuer', label: 'IdP issuer override', when: saml, hint: `Empty uses ${p.name}'s format.` },
      { k: 'relayState', label: 'Default RelayState for IdP-initiated sign-in', when: saml },
      { k: 'encryptAssertion', label: 'Encrypt assertions', type: 'bool', when: saml },
      { k: 'spEncryptionCert', label: 'SP encryption certificate', type: 'textarea', when: v => saml(v) && v.encryptAssertion, placeholder: '-----BEGIN CERTIFICATE-----',
        hint: 'PEM, bare base64, or paste the SP\'s whole metadata XML. For the built-in test SP, copy its certificate from Overview.' },
      { k: 'encryptionAlg', label: 'Block cipher', type: 'select', when: v => saml(v) && v.encryptAssertion,
        options: [['aes256-cbc', 'AES-256-CBC (Okta, Entra default)'], ['aes128-cbc', 'AES-128-CBC'], ['aes256-gcm', 'AES-256-GCM'], ['aes128-gcm', 'AES-128-GCM']] },
      { k: 'keyTransportAlg', label: 'Key transport', type: 'select', when: v => saml(v) && v.encryptAssertion,
        options: [['rsa-oaep', 'RSA-OAEP (recommended)'], ['rsa-1_5', 'RSA 1.5 (legacy)']] },
      { k: 'spSigningCert', label: 'SP signing certificate (verifies signed AuthnRequests)', type: 'textarea', when: saml, placeholder: '-----BEGIN CERTIFICATE-----',
        hint: 'Empty: signed requests are accepted without checking the signature. PEM, base64 or SP metadata.' },
      { k: 'requireSignedRequests', label: 'Require signed AuthnRequests', type: 'bool', when: saml },
      { k: 'redirectUris', label: 'Redirect URIs', type: 'lines', when: oidc, hint: 'One per line. Matched exactly, as real IdPs do.' },
      { k: 'postLogoutRedirectUris', label: 'Post-logout redirect URIs', type: 'lines', when: oidc },
      { k: 'clientId', label: 'Client ID', when: oidc, hint: isNew ? `Empty generates one in ${p.name}'s format.` : '' },
      { k: 'public', label: 'Public client (SPA or mobile: no secret)', type: 'bool', when: oidc },
      { k: 'clientSecret', label: 'Client secret', when: v => oidc(v) && !v.public, hint: isNew ? 'Empty generates one.' : '' },
      { k: 'requirePkce', label: 'Require PKCE', type: 'bool', when: oidc },
      { k: 'groupsClaim', label: 'Include a groups claim', type: 'bool', when: oidc },
      { k: 'idTokenTtl', label: 'ID token lifetime, seconds (0 = 3600)', type: 'number', when: oidc },
      { k: 'accessTokenTtl', label: 'Access token lifetime, seconds (0 = 3600)', type: 'number', when: oidc },
    ],
    submit: async v => {
      if (isNew) {
        if (!v.attributes || !v.attributes.length) delete v.attributes;
        if (!v.clientId) delete v.clientId;
        if (!v.clientSecret) delete v.clientSecret;
        if (v.type === 'saml' && !v.nameIdFormat) delete v.nameIdFormat;
        await api('POST', tp('/apps'), v);
      } else {
        await api('PATCH', tp('/apps/' + encodeURIComponent(a.id)), v);
      }
      toast('Saved');
      await refreshTenant();
    },
  });
}

function targetForm(g) {
  form({
    title: g ? 'Edit ' + g.name : 'Add SCIM target', values: g || { autoPush: false, flavor: '' },
    fields: [
      { k: 'name', label: 'Name', placeholder: 'My app' },
      { k: 'baseUrl', label: 'SCIM base URL', placeholder: 'http://localhost:3000/scim/v2', hint: 'Requests go to {base}/Users and {base}/Groups. Inside Docker, reach your machine at http://host.docker.internal.' },
      { k: 'token', label: 'Bearer token', type: 'password', hint: 'Sent as Authorization: Bearer …, or verbatim if it starts with "Basic ".' },
      { k: 'flavor', label: 'Client behaviour', type: 'select', options: [['', `Same as the tenant (${prov(S.t.provider).name})`], ...S.info.providers.filter(p => SCIM_FLAVORS.includes(p.key)).map(p => [p.key, p.name])] },
      { k: 'autoPush', label: 'Auto-push: provision on every user and group change', type: 'bool' },
    ],
    submit: async v => {
      if (g) await api('PATCH', tp('/scim-targets/' + encodeURIComponent(g.id)), v);
      else await api('POST', tp('/scim-targets'), v);
      await refreshTenant();
    },
  });
}

async function confirmDo(msg, fn) { if (confirm(msg)) await fn(); }

// ---- actions ----
const A = {
  copy: d => navigator.clipboard.writeText(d.v).then(() => toast('Copied'), () => toast('Copy failed', true)),
  'new-tenant': () => form({
    title: 'New tenant', okLabel: 'Create', values: { provider: 'okta', seed: true },
    fields: [
      { k: 'name', label: 'Name', placeholder: 'Acme Corp' },
      { k: 'provider', label: 'Provider to simulate', type: 'select', options: S.info.providers.map(p => [p.key, p.name]) },
      { k: 'domain', label: 'Domain', placeholder: 'acme.example', hint: 'Seeded users get addresses at this domain.' },
      { k: 'seed', label: 'Add sample users, groups and the built-in test apps', type: 'bool' },
    ],
    submit: async v => { const t = await api('POST', '/tenants', v); await loadTenants(); return () => { location.hash = '#/t/' + t.id; }; },
  }),
  'reset-all': () => confirmDo('Delete every tenant and recreate the demo data?', async () => { await api('POST', '/reset'); await loadTenants(); route(); toast('Demo data restored'); }),
  'delete-tenant': () => confirmDo(`Delete ${S.t.name} and everything in it?`, async () => { await api('DELETE', tp('')); await loadTenants(); location.hash = '#/'; }),
  rotate: () => confirmDo('Rotate the signing key? Apps holding the old certificate will start failing.', async () => { await api('POST', tp('/rotate-keys')); toast('Key rotated'); await refreshTenant(); }),
  'user-new': () => userForm(),
  'user-edit': d => userForm(S.t.users.find(u => u.id === d.id)),
  'user-del': d => confirmDo('Delete this user?', async () => { await api('DELETE', tp('/users/' + encodeURIComponent(d.id))); await refreshTenant(); }),
  'gen-users': async () => { const r = await api('POST', tp('/users/generate'), { count: 25 }); toast(`Added ${r.created} users`); await refreshTenant(); },
  autologin: async d => {
    const off = S.t.simulations.autoLogin === d.id;
    await api('PATCH', tp('/simulations'), { autoLogin: off ? '' : d.id });
    toast(off ? 'Auto sign-in off' : `Sign-ins now skip the login page as ${d.id}`);
    await refreshTenant();
  },
  'group-new': () => groupForm(),
  'group-edit': d => groupForm(S.t.groups.find(g => g.id === d.id)),
  'group-del': d => confirmDo('Delete this group?', async () => { await api('DELETE', tp('/groups/' + encodeURIComponent(d.id))); await refreshTenant(); }),
  'app-new': d => appForm(d.type === 'saml' ? { type: 'saml', signResponse: false, signAssertion: false, encryptionAlg: 'aes256-cbc', keyTransportAlg: 'rsa-oaep' } : { type: 'oidc', redirectUris: ['http://localhost:3000/callback'] }),
  'app-edit': d => appForm(S.t.apps.find(a => a.id === d.id)),
  'app-del': d => confirmDo('Delete this app?', async () => { await api('DELETE', tp('/apps/' + encodeURIComponent(d.id))); await refreshTenant(); }),
  mint: d => form({
    title: 'Mint tokens without a browser', okLabel: 'Mint', values: { scope: 'openid profile email offline_access' },
    fields: [{ k: 'user', label: 'User', type: 'select', options: userOptions() }, { k: 'scope', label: 'Scope' }, { k: 'nonce', label: 'Nonce (optional)' }],
    submit: async v => {
      const r = await api('POST', tp(`/apps/${d.id}/tokens`), v);
      const sec = [];
      if (r.id_token) sec.push(['ID token (decoded)', JSON.stringify(jwt(r.id_token), null, 2)], ['ID token', r.id_token]);
      sec.push(['Access token (decoded)', JSON.stringify(jwt(r.access_token), null, 2)], ['Token response', JSON.stringify(r, null, 2)]);
      return () => showResult('Tokens (simulations applied)', sec);
    },
  }),
  'mk-saml': d => form({
    title: 'Make a SAMLResponse without a browser', okLabel: 'Make',
    fields: [{ k: 'user', label: 'User', type: 'select', options: userOptions() }, { k: 'inResponseTo', label: 'InResponseTo (optional)', hint: 'The ID of your AuthnRequest. Empty makes an IdP-initiated response.' }, { k: 'relayState', label: 'RelayState (optional)' }],
    submit: async v => {
      const r = await api('POST', tp(`/apps/${d.id}/saml-response`), v);
      const dec = await api('POST', '/decode', { input: r.xml });
      const curl = `curl -X POST '${r.acsUrl}' \\\n  --data-urlencode 'SAMLResponse=${r.samlResponse}'${r.relayState ? ` \\\n  --data-urlencode 'RelayState=${r.relayState}'` : ''}`;
      return () => showResult('SAMLResponse (simulations applied)', [['Decoded', dec.xml || r.xml], ['POST it to the ACS', curl], ['SAMLResponse (base64)', r.samlResponse]]);
    },
  }),
  'target-new': () => targetForm(),
  'target-edit': d => targetForm(S.t.scimTargets.find(g => g.id === d.id)),
  'target-del': d => confirmDo('Delete this SCIM target?', async () => { await api('DELETE', tp('/scim-targets/' + encodeURIComponent(d.id))); await refreshTenant(); }),
  scim: async (d, el) => {
    const label = el.textContent;
    el.disabled = true;
    el.textContent = 'Running…';
    try {
      const body = d.k === 'conformance' ? { flavor: $('#flv-' + d.id).value } : {};
      const r = await api('POST', tp(`/scim-targets/${d.id}/${d.k}`), body);
      toast(`${r.passed} passed, ${r.failed} failed, ${r.warned} warnings`, r.failed > 0);
      await refreshTenant();
    } finally { el.disabled = false; el.textContent = label; }
  },
  'scim-push': d => form({
    title: 'Push one user or group', okLabel: 'Push', values: { kind: 'user', action: 'upsert' },
    fields: [
      { k: 'kind', label: 'What', type: 'select', options: [['user', 'User'], ['group', 'Group']] },
      { k: 'user', label: 'User', type: 'select', options: userOptions(), when: v => v.kind === 'user' },
      { k: 'group', label: 'Group', type: 'select', options: S.t.groups.map(g => [g.id, g.name]), when: v => v.kind === 'group' },
      { k: 'action', label: 'Action', type: 'select', options: [['upsert', 'Create or update'], ['deactivate', 'Deactivate'], ['delete', 'Delete (as this provider deletes)']] },
    ],
    submit: async v => {
      const r = await api('POST', tp(`/scim-targets/${d.id}/push`), { kind: v.kind, id: v.kind === 'user' ? v.user : v.group, action: v.action });
      toast(r.checks.map(c => `${c.name}: ${c.detail}`).join(' · '), r.failed > 0);
      await refreshTenant();
    },
  }),
  'sims-reset': async () => { await api('DELETE', tp('/simulations')); toast('All simulations off'); await refreshTenant(); },
  preset: async d => { await api('POST', tp('/simulations/presets/' + d.k)); toast('Preset applied'); await refreshTenant(); },
  'sel-log': d => {
    S.sel = +d.id;
    $$('.logrow').forEach(r => r.classList.toggle('sel', +r.dataset.id === S.sel));
    if (S.view === 'logs') history.replaceState(null, '', '#/logs/' + S.sel);
    drawDetail();
  },
  pause: (d, el) => { S.paused = !S.paused; el.textContent = S.paused ? 'Resume' : 'Pause'; if (!S.paused) drawLogList(); },
  'clear-logs': async () => { await api('DELETE', '/logs'); S.logs = []; S.sel = null; drawLogList(); drawDetail(); },
  'export-logs': () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(S.logs.filter(matches), null, 2)], { type: 'application/json' }));
    a.download = `mock-idp-logs-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
  },
  'copy-curl': d => A.copy({ v: curlOf(S.logs.find(e => e.id === +d.id)) }),
  'copy-json': d => A.copy({ v: JSON.stringify(S.logs.find(e => e.id === +d.id), null, 2) }),
  decode: async () => { const r = await api('POST', '/decode', { input: $('#dec-in').value }); $('#dec-out').innerHTML = part(decodedView(r)); },
};

document.addEventListener('click', async e => {
  const el = e.target.closest('[data-act]');
  if (!el || !A[el.dataset.act]) return;
  e.preventDefault();
  try { await A[el.dataset.act](el.dataset, el); } catch (err) { toast(err.message, true); }
});

document.addEventListener('change', async e => {
  const el = e.target;
  if (el.dataset.sim) {
    let v = el.type === 'checkbox' ? el.checked : el.value;
    if (el.type === 'number') v = parseInt(v || '0', 10) || 0;
    try {
      await api('PATCH', tp('/simulations'), { [el.dataset.sim]: v });
      toast(v ? `On: ${el.getAttribute('aria-label')}` : `Off: ${el.getAttribute('aria-label')}`);
      await refreshTenant();
    } catch (err) { toast(err.message, true); }
  } else if (el.id === 'lkind') { S.lf.kind = el.value; drawLogList(); }
  else if (el.id === 'ltenant') { S.lf.tenant = el.value; drawLogList(); }
});

document.addEventListener('input', e => { if (e.target.id === 'lq') { S.lf.q = e.target.value; drawLogList(); } });

// ---- live updates ----
let refreshTimer;
function scheduleRefresh(tenant) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(async () => {
    await loadTenants();
    const parts = location.hash.replace(/^#\/?/, '').split('/');
    if (S.view === 't' && (!tenant || tenant === S.t?.id) && !dlg().open && parts[2] !== 'logs') await refreshTenant();
    else if (S.view === '') homePage();
  }, 300);
}

function connect() {
  const tok = store.get('token');
  const es = new EventSource('/api/logs/stream' + (tok ? '?token=' + encodeURIComponent(tok) : ''));
  const dot = $('#live-dot');
  es.onopen = () => dot.classList.add('on');
  es.onerror = () => dot.classList.remove('on');
  es.addEventListener('log', ev => {
    const e = JSON.parse(ev.data);
    S.logs.push(e);
    if (S.logs.length > 2000) S.logs.shift();
    dot.classList.remove('blink'); void dot.offsetWidth; dot.classList.add('blink');
    const list = $('#loglist');
    if (list && !S.paused && matches(e)) {
      $('#logempty')?.remove();
      list.insertAdjacentHTML('afterbegin', part(logRow(e)));
    }
  });
  es.addEventListener('change', ev => scheduleRefresh(JSON.parse(ev.data).tenant));
}

(async function boot() {
  [S.info, S.routes, { certificatePem: S.spCert }] = await Promise.all([api('GET', '/info'), api('GET', ''), api('GET', '/test-sp-certificate')]);
  await loadTenants();
  S.logs = await api('GET', '/logs?limit=1000');
  connect();
  route();
})().catch(e => main(html`<div class="card err">Could not reach the mock-idp API: ${e.message}</div>`));
