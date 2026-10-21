// Interop tests: real, widely used Node libraries against a running mock-idp.
// Run through ../run.sh, or set MOCKIDP_URL to a running instance.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { SAML } from '@node-saml/node-saml';
import * as oidc from 'openid-client';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

import { BASE, api, unescapeHTML } from './helpers.mjs';

const TENANTS = {
  okta: 'acme.example', entra: 'contoso.example', google: 'globex.example', onelogin: 'initech.example',
  pingone: 'umbrella.example', jumpcloud: 'hooli.example', adfs: 'wayne.example', auth0: 'stark.example', keycloak: 'cyberdyne.example',
};
const alice = t => `alice@${TENANTS[t]}`;

// sims replaces the tenant's simulations; autoLogin skips the login page.
async function sims(tenant, s = {}) {
  await api('DELETE', `/tenants/${tenant}/simulations`);
  await api('PATCH', `/tenants/${tenant}/simulations`, { autoLogin: alice(tenant), ...s });
}

// The fault matrix: what each library does with each simulation.
const matrix = {};
function record(lib, sim, outcome) { (matrix[sim] ||= {})[lib] = outcome; }
after(() => {
  console.log('\nFault matrix (rejected = the library caught it)\n');
  console.table(Object.fromEntries(Object.entries(matrix).map(([k, v]) => [k, Object.fromEntries(Object.entries(v).map(([l, o]) => [l, o.slice(0, 70)]))])));
});

async function outcome(fn) {
  try { const v = await fn(); return { ok: true, v, text: 'ACCEPTED' }; } catch (e) { return { ok: false, text: 'rejected: ' + e.message.split('\n')[0] }; }
}

// ---------- SAML: @node-saml/node-saml ----------

async function samlApp(tenant, entityId) {
  const ep0 = await api('GET', `/tenants/${tenant}/endpoints`);
  if (!ep0.apps.find(a => a.spEntityId === entityId)) {
    await api('POST', `/tenants/${tenant}/apps`, { type: 'saml', name: 'node-saml', entityId, acsUrl: 'https://sp.example/acs' });
  }
  const ep = await api('GET', `/tenants/${tenant}/endpoints`);
  return { app: ep.apps.find(a => a.spEntityId === entityId), cert: ep.certificatePem };
}

function nodeSaml({ app, cert }) {
  return new SAML({
    entryPoint: app.ssoUrl, issuer: app.spEntityId, callbackUrl: app.acsUrl, audience: app.spEntityId,
    idpCert: cert, idpIssuer: app.idpEntityId, wantAssertionsSigned: true, wantAuthnResponseSigned: false,
    validateInResponseTo: 'always', acceptedClockSkewMs: 60_000, identifierFormat: null,
  });
}

async function samlLogin(saml) {
  const url = await saml.getAuthorizeUrlAsync('relay-1', undefined, {});
  const r = await fetch(url, { redirect: 'manual' });
  const body = await r.text();
  const m = body.match(/name="SAMLResponse" value="([^"]+)"/);
  if (!m) throw new Error(`IdP sent no SAMLResponse (HTTP ${r.status}): ${body.slice(0, 160)}`);
  return saml.validatePostResponseAsync({ SAMLResponse: unescapeHTML(m[1]) });
}

test('node-saml: sign-in works on every provider', async t => {
  for (const tenant of Object.keys(TENANTS)) {
    await t.test(tenant, async () => {
      await sims(tenant);
      const saml = nodeSaml(await samlApp(tenant, 'urn:interop:node-saml'));
      const { profile } = await samlLogin(saml);
      assert.ok(profile.nameID, 'has a NameID');
      assert.match(profile.nameID, /alice|^[\w|-]+$/, `NameID ${profile.nameID}`);
      assert.equal(profile.issuer, (await samlApp(tenant, 'urn:interop:node-saml')).app.idpEntityId);
    });
  }
});

test('node-saml: provider attribute shapes arrive', async () => {
  await sims('entra');
  const { profile } = await samlLogin(nodeSaml(await samlApp('entra', 'urn:interop:node-saml')));
  assert.equal(profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'], alice('entra'));
  assert.ok(profile['http://schemas.microsoft.com/identity/claims/tenantid'], 'Entra tenantid claim');
  await sims('okta');
  const okta = (await samlLogin(nodeSaml(await samlApp('okta', 'urn:interop:node-saml')))).profile;
  assert.equal(okta.firstName, 'Alice');
  assert.deepEqual([okta.groups].flat().sort(), ['Admins', 'Engineering', 'Everyone']);
});

// Faults a correct SP must refuse. A library that accepts one fails the test.
// node-saml 5.1 checks idpIssuer only on logout messages, so a wrong issuer on
// a login response is information, not a failure (the pinned cert still holds).
const SAML_MUST_REJECT = ['samlExpired', 'samlNotYetValid', 'samlBadSignature', 'samlWrongCert', 'samlUnsigned', 'samlWrongAudience',
  'samlWrongInResponseTo', 'samlSignatureWrapping'];
const SAML_INFO = ['samlWrongIssuer', 'samlSha1', 'samlWrongDestination', 'samlWrongRecipient', 'samlMissingNameId', 'samlNoAttributes', 'samlCommentInjection'];

test('node-saml: faults', async t => {
  const saml = nodeSaml(await samlApp('okta', 'urn:interop:node-saml'));
  await sims('okta');
  await samlLogin(saml); // a normal sign-in must work before faults mean anything
  for (const sim of [...SAML_MUST_REJECT, ...SAML_INFO, 'authError:access_denied', 'clockSkewSec:300']) {
    await t.test(sim, async () => {
      const [k, v] = sim.split(':');
      await sims('okta', { [k]: v === undefined ? true : isNaN(v) ? v : +v });
      const o = await outcome(() => samlLogin(saml));
      if (o.ok && k === 'samlCommentInjection') o.text = `ACCEPTED, NameID read as ${o.v.profile.nameID}`;
      record('node-saml', sim, o.text);
      if (SAML_MUST_REJECT.includes(k) || k === 'authError') assert.equal(o.ok, false, `${sim} was accepted`);
      if (k === 'samlCommentInjection' && o.ok) assert.notEqual(o.v.profile.nameID, alice('okta'), 'comment injection truncated the NameID');
    });
  }
  await sims('okta');
});

// ---------- OIDC: openid-client ----------

const REDIRECT = 'https://rp.example/callback';

async function oidcApp(tenant, name, extra = {}) {
  const t = await api('GET', `/tenants/${tenant}`);
  return t.apps.find(a => a.name === name) || api('POST', `/tenants/${tenant}/apps`, { type: 'oidc', name, redirectUris: [REDIRECT], ...extra });
}

async function rp(tenant, { strict = false, publicClient = false } = {}) {
  const app = await oidcApp(tenant, publicClient ? 'openid-client-spa' : 'openid-client', publicClient ? { public: true, requirePkce: true } : {});
  const config = await oidc.discovery(new URL(`${BASE}/t/${tenant}`), app.clientId, publicClient ? undefined : app.clientSecret,
    publicClient ? oidc.None() : undefined, { execute: [oidc.allowInsecureRequests] });
  if (strict) oidc.enableNonRepudiationChecks(config);
  return config;
}

// codeFlow runs authorization code + PKCE. With a cookie jar it goes
// through the real login page.
async function codeFlow(config, { scope = 'openid profile email offline_access', login } = {}) {
  const verifier = oidc.randomPKCECodeVerifier();
  const state = oidc.randomState(), nonce = oidc.randomNonce();
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT, scope, state, nonce, code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
  });
  let loc = url.href;
  const cookies = login?.cookies || {};
  for (let i = 0; i < 6 && !loc.startsWith(REDIRECT); i++) {
    const r = await fetch(loc, { redirect: 'manual', headers: { cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ') } });
    for (const c of r.headers.getSetCookie()) { const [kv] = c.split(';'); const [k, v] = kv.split('='); if (v) cookies[k] = v; else delete cookies[k]; }
    if (r.status === 200 && login) {
      // Fill each page the IdP shows (password, then MFA) until it redirects.
      let page = await r.text(), p;
      const tenant = loc.split('/t/')[1].split('/')[0];
      for (;;) {
        const i = page.match(/name="i" value="([^"]+)"/)?.[1];
        if (!i) throw new Error('login refused: ' + (page.match(/class="err">([^<]+)/)?.[1] || 'unexpected page'));
        const mfa = page.includes('name="code"');
        login.pages?.push(mfa ? 'mfa' : 'login');
        p = await fetch(new URL(`/t/${tenant}/login`, BASE), {
          method: 'POST', redirect: 'manual',
          body: new URLSearchParams(mfa ? { i, step: 'mfa', code: '123456' } : { i, step: 'password', username: login.user, password: login.password }),
          headers: { cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ') },
        });
        for (const c of p.headers.getSetCookie()) { const [kv] = c.split(';'); const [k, v] = kv.split('='); cookies[k] = v; }
        if (p.status !== 200) break;
        page = await p.text();
        if (page.match(/class="err">/)) throw new Error('login refused: ' + page.match(/class="err">([^<]+)/)[1]);
      }
      loc = new URL(p.headers.get('location'), BASE).href;
      continue;
    }
    if (r.status !== 302) throw new Error(`authorize answered HTTP ${r.status}: ${(await r.text()).slice(0, 120)}`);
    loc = new URL(r.headers.get('location'), BASE).href;
  }
  return oidc.authorizationCodeGrant(config, new URL(loc), { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
}

test('openid-client: code + PKCE, userinfo and refresh on every provider', async t => {
  for (const tenant of Object.keys(TENANTS)) {
    await t.test(tenant, async () => {
      await sims(tenant);
      const config = await rp(tenant, { strict: true });
      const tokens = await codeFlow(config);
      const claims = tokens.claims();
      assert.ok(claims.sub);
      const info = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
      assert.equal(info.sub, claims.sub);
      assert.ok(tokens.refresh_token, 'refresh token for offline_access');
      const again = await oidc.refreshTokenGrant(config, tokens.refresh_token);
      assert.equal(again.claims().sub, claims.sub);
      await assert.rejects(oidc.refreshTokenGrant(config, tokens.refresh_token), e => e.cause?.error === 'invalid_grant', 'refresh tokens rotate');
    });
  }
});

test('openid-client: provider claim quirks', async () => {
  await sims('entra');
  const entra = (await codeFlow(await rp('entra'))).claims();
  assert.ok(entra.oid && entra.tid, 'Entra sends oid and tid');
  assert.notEqual(entra.sub, entra.oid, 'Entra sub is pairwise, not the object id');
  assert.equal(entra.email_verified, undefined, 'Entra sends no email_verified');
  await sims('google');
  const google = (await codeFlow(await rp('google'))).claims();
  assert.match(google.sub, /^\d{21}$/);
  assert.equal(google.hd, TENANTS.google);
});

test('openid-client: public client (SPA) with PKCE', async () => {
  await sims('okta');
  const tokens = await codeFlow(await rp('okta', { publicClient: true }));
  assert.ok(tokens.id_token);
});

test('openid-client: the real login page, SSO session, wrong password, MFA', async () => {
  await api('DELETE', '/tenants/okta/simulations');
  const config = await rp('okta');
  const login = { user: alice('okta'), password: 'password', cookies: {}, pages: [] };
  await codeFlow(config, { login });
  assert.deepEqual(login.pages, ['login']);
  login.pages = [];
  await codeFlow(config, { login });
  assert.deepEqual(login.pages, [], 'second sign-in reuses the IdP session');
  await assert.rejects(codeFlow(config, { login: { ...login, cookies: {}, password: 'nope' } }), /Wrong username or password/);
  await assert.rejects(codeFlow(config, { login: { user: 'carol@acme.example', password: 'password', cookies: {} } }), /deactivated/);
  await api('PATCH', '/tenants/okta/simulations', { requireMfa: true });
  const mfa = { user: alice('okta'), password: 'password', cookies: {}, pages: [] };
  const tokens = await codeFlow(config, { login: mfa });
  assert.deepEqual(mfa.pages, ['login', 'mfa']);
  assert.deepEqual(tokens.claims().amr, ['pwd', 'mfa']);
  await api('DELETE', '/tenants/okta/simulations');
});

const OIDC_MUST_REJECT = ['oidcExpired', 'oidcWrongIssuer', 'oidcWrongAudience', 'oidcWrongNonce', 'oidcWrongState', 'oidcAlgNone',
  'authError:access_denied', 'tokenError:invalid_grant', 'httpStatus:503'];
const OIDC_SIGNATURE = ['oidcBadSignature', 'oidcUnknownKid'];
const OIDC_INFO = ['oidcWrongAtHash', 'oidcMissingEmail', 'oidcEmailUnverified', 'clockSkewSec:300'];

for (const strict of [false, true]) {
  const lib = strict ? 'openid-client (non-repudiation on)' : 'openid-client (default)';
  test(`${lib}: faults`, async t => {
    await sims('okta');
    const config = await rp('okta', { strict });
    await codeFlow(config); // a normal sign-in must work before faults mean anything
    for (const sim of [...OIDC_MUST_REJECT, ...OIDC_SIGNATURE, ...OIDC_INFO]) {
      await t.test(sim, async () => {
        const [k, v] = sim.split(':');
        await sims('okta', { [k]: v === undefined ? true : isNaN(v) ? v : +v });
        const o = await outcome(() => codeFlow(config));
        await sims('okta');
        record(lib, sim, o.text);
        if (OIDC_MUST_REJECT.includes(sim) || (strict && OIDC_SIGNATURE.includes(sim))) assert.equal(o.ok, false, `${sim} was accepted`);
      });
    }
  });
}

// ---------- MCP: the official SDK ----------

test('MCP SDK: connect, list tools, drive a simulation', async () => {
  const client = new Client({ name: 'interop', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(BASE + '/mcp')));
  const { tools } = await client.listTools();
  assert.ok(tools.length >= 30, `${tools.length} tools`);
  assert.ok(tools.find(t => t.name === 'set_simulations').inputSchema.required.includes('tenant'));
  const set = await client.callTool({ name: 'set_simulations', arguments: { tenant: 'okta', body: { samlExpired: true } } });
  assert.equal(set.isError, false);
  const got = JSON.parse((await client.callTool({ name: 'get_simulations', arguments: { tenant: 'okta' } })).content[0].text);
  assert.equal(got.samlExpired, true);
  const bad = await client.callTool({ name: 'get_tenant', arguments: { tenant: 'nope' } });
  assert.equal(bad.isError, true);
  await client.callTool({ name: 'reset_simulations', arguments: { tenant: 'okta' } });
  const logs = JSON.parse((await client.callTool({ name: 'list_logs', arguments: { tenant: 'okta', limit: '5' } })).content[0].text);
  assert.ok(Array.isArray(logs));
  await client.close();
});

// Entra signs only the assertion, so a forged assertion beside it breaks no
// signature. This is the case signature wrapping attacks target.
test('node-saml: signature wrapping with assertion-only signing (Entra)', async () => {
  await sims('entra', { samlSignatureWrapping: true });
  const saml = nodeSaml(await samlApp('entra', 'urn:interop:node-saml'));
  const o = await outcome(() => samlLogin(saml));
  await sims('entra');
  record('node-saml', 'samlSignatureWrapping (assertion-only signing)', o.ok ? `ACCEPTED as ${o.v.profile.nameID}` : o.text);
  assert.notEqual(o.ok && o.v.profile.nameID, 'attacker@evil.example', 'signed in as the attacker');
});
