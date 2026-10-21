import { after } from 'node:test';
// Shared by the interop test files.
export const BASE = process.env.MOCKIDP_URL || 'http://localhost:7171';

export async function api(method, path, body) {
  const r = await fetch(BASE + '/api' + path, { method, headers: { 'content-type': 'application/json' }, body: body && JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(`${method} ${path}: ${j.error}`);
  return j;
}

export const unescapeHTML = s => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
  .replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

// formFields reads the hidden inputs of an auto-POST page.
export function formFields(html) {
  const action = html.match(/action="([^"]+)"/)?.[1];
  const fields = {};
  for (const m of html.matchAll(/name="([^"]+)" value="([^"]*)"/g)) fields[m[1]] = unescapeHTML(m[2]);
  return { action: action && unescapeHTML(action), fields };
}

// A tiny cookie-keeping browser: follows redirects by hand so tests can see each hop.
export class Browser {
  constructor() { this.cookies = {}; }
  header() { return Object.entries(this.cookies).map(([k, v]) => `${k}=${v}`).join('; '); }
  keep(res) {
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const [k, v] = kv.split('=');
      if (!v || /max-age=0|max-age=-/i.test(c)) delete this.cookies[k]; else this.cookies[k] = v;
    }
  }
  async get(url) {
    const r = await fetch(url, { redirect: 'manual', headers: { cookie: this.header() } });
    this.keep(r);
    return { status: r.status, location: r.headers.get('location') && new URL(r.headers.get('location'), url).href, body: await r.text() };
  }
  async post(url, form) {
    const r = await fetch(url, { method: 'POST', redirect: 'manual', body: new URLSearchParams(form), headers: { cookie: this.header() } });
    this.keep(r);
    return { status: r.status, location: r.headers.get('location') && new URL(r.headers.get('location'), url).href, body: await r.text() };
  }
  // pickUser answers a mock-idp login page by clicking a test user.
  async pickUser(loginPage, tenant, userId) {
    const i = loginPage.body.match(/name="i" value="([^"]+)"/)[1];
    return this.post(`${BASE}/t/${tenant}/login`, { i, step: 'pick', user: userId });
  }
}

// newTenant makes an isolated tenant so a test's faults and key rotations
// touch nothing else. It is deleted when the test file finishes.
const made = [];
after(() => Promise.all(made.map(id => api('DELETE', `/tenants/${id}`).catch(() => {}))));
export async function newTenant(provider) {
  const t = await api('POST', '/tenants', { name: `edge ${provider} ${Math.random().toString(36).slice(2, 7)}`, provider });
  made.push(t.id);
  const user = login => t.users.find(u => u.userName.startsWith(login + '@') || u.userName.startsWith(login + '_'));
  return { ...t, user };
}
