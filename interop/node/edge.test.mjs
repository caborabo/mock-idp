// Edge cases: the flows real apps hit after the happy path. Each test makes its
// own tenant, so nothing here depends on, or disturbs, another test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { SAML } from '@node-saml/node-saml';
import * as oidc from 'openid-client';
import { BASE, api, formFields, Browser, newTenant } from './helpers.mjs';

// ---------- SAML ----------

async function samlSetup(t, extra = {}) {
  await api('POST', `/tenants/${t.id}/apps`, { type: 'saml', name: 'edge-sp', entityId: 'urn:edge:sp', acsUrl: 'https://sp.example/acs', ...extra });
  const ep = await api('GET', `/tenants/${t.id}/endpoints`);
  return { app: ep.apps.find(a => a.spEntityId === 'urn:edge:sp'), cert: ep.certificatePem };
}

function nodeSaml({ app, cert }, opts = {}) {
  return new SAML({
    entryPoint: app.ssoUrl, logoutUrl: app.sloUrl, issuer: app.spEntityId, callbackUrl: app.acsUrl, audience: app.spEntityId,
    idpCert: cert, idpIssuer: app.idpEntityId, wantAssertionsSigned: true, wantAuthnResponseSigned: false,
    validateInResponseTo: 'always', acceptedClockSkewMs: 60_000, identifierFormat: null, ...opts,
  });
}

const autoLogin = (t, userName, more = {}) => api('PATCH', `/tenants/${t.id}/simulations`, { autoLogin: userName, ...more });

test('SAML: RelayState comes back unchanged', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const saml = nodeSaml(await samlSetup(t));
  const page = await new Browser().get(await saml.getAuthorizeUrlAsync('return-to=/billing?x=1&y=2', undefined, {}));
  const { action, fields } = formFields(page.body);
  assert.equal(action, 'https://sp.example/acs');
  assert.equal(fields.RelayState, 'return-to=/billing?x=1&y=2');
  await saml.validatePostResponseAsync({ SAMLResponse: fields.SAMLResponse });
});

test('SAML: IdP-initiated sign-in is accepted only when the SP allows it', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const setup = await samlSetup(t, { relayState: '/dashboard' });
  const page = await new Browser().get(setup.app.idpInitiatedUrl);
  const { fields } = formFields(page.body);
  assert.equal(fields.RelayState, '/dashboard', 'default RelayState for IdP-initiated');
  await assert.rejects(nodeSaml(setup).validatePostResponseAsync({ SAMLResponse: fields.SAMLResponse }), /InResponseTo/,
    'an SP that requires InResponseTo must refuse an unsolicited response');
  const { profile } = await nodeSaml(setup, { validateInResponseTo: 'never' }).validatePostResponseAsync({ SAMLResponse: fields.SAMLResponse });
  assert.equal(profile.nameID, t.user('alice').userName);
});

test('SAML: the login page, the IdP session, and ForceAuthn', async () => {
  const t = await newTenant('okta');
  const setup = await samlSetup(t);
  const b = new Browser();
  const login = async (saml) => {
    const first = await b.get(await saml.getAuthorizeUrlAsync('', undefined, {}));
    let page = first.body, sawLogin = false;
    if (first.status !== 200) {
      const loginPage = await b.get(first.location);
      assert.match(loginPage.body, /Sign in/);
      page = (await b.pickUser(loginPage, t.id, t.user('bob').id)).body;
      sawLogin = true;
    }
    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: formFields(page).fields.SAMLResponse });
    return { sawLogin, profile };
  };
  let r = await login(nodeSaml(setup));
  assert.equal(r.sawLogin, true, 'first sign-in shows the login page');
  assert.equal(r.profile.nameID, t.user('bob').userName);
  r = await login(nodeSaml(setup));
  assert.equal(r.sawLogin, false, 'second sign-in rides the IdP session');
  r = await login(nodeSaml(setup, { forceAuthn: true }));
  assert.equal(r.sawLogin, true, 'ForceAuthn="true" must show the login page again');
});

test('SAML: non-ASCII names and Entra guest UPNs survive signing', async () => {
  const t = await newTenant('entra');
  const setup = await samlSetup(t);
  const zoe = t.user('zoe');
  await autoLogin(t, zoe.userName);
  const saml = nodeSaml(setup);
  const p1 = formFields((await new Browser().get(await saml.getAuthorizeUrlAsync('', undefined, {}))).body);
  const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: p1.fields.SAMLResponse });
  assert.equal(profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'], 'Ñúñez-O\'Brien');
  const guest = t.users.find(u => u.userName.includes('#EXT#'));
  await autoLogin(t, guest.userName);
  const p2 = formFields((await new Browser().get(await saml.getAuthorizeUrlAsync('', undefined, {}))).body);
  const g = (await saml.validatePostResponseAsync({ SAMLResponse: p2.fields.SAMLResponse })).profile;
  assert.equal(g.nameID, guest.userName, 'the #EXT# UPN arrives intact');
});

test('SAML: single logout over HTTP-Redirect gets a signed Redirect reply and ends the session', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const setup = await samlSetup(t, { sloUrl: 'https://sp.example/slo' });
  const saml = nodeSaml(setup);
  const b = new Browser();
  const { fields } = formFields((await b.get(await saml.getAuthorizeUrlAsync('', undefined, {}))).body);
  const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: fields.SAMLResponse });
  assert.ok(Object.keys(b.cookies).length, 'an IdP session cookie exists');
  const out = await b.get(await saml.getLogoutUrlAsync(profile, 'bye', {}));
  assert.equal(out.status, 302);
  const back = new URL(out.location);
  assert.equal(back.origin + back.pathname, 'https://sp.example/slo');
  const res = await saml.validateRedirectAsync(Object.fromEntries(back.searchParams), back.search.slice(1));
  assert.equal(res.loggedOut, true, 'node-saml verified the query-string signature and InResponseTo');
  assert.equal(back.searchParams.get('RelayState'), 'bye');
  assert.equal(Object.keys(b.cookies).length, 0, 'IdP session cookie cleared');
});

// node-saml reads InResponseTo from <Response> only, never <LogoutResponse>,
// on the POST path -- so a POST-binding logout reply can only be checked with
// validateInResponseTo 'ifPresent'. Recorded here so the behaviour is known.
test('SAML: single logout over HTTP-POST gets a signed POST reply', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const setup = await samlSetup(t, { sloUrl: 'https://sp.example/slo' });
  const saml = nodeSaml(setup);
  const b = new Browser();
  const { fields } = formFields((await b.get(await saml.getAuthorizeUrlAsync('', undefined, {}))).body);
  const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: fields.SAMLResponse });
  const logoutURL = new URL(await saml.getLogoutUrlAsync(profile, 'bye', {}));
  const out = await b.post(setup.app.sloUrl, Object.fromEntries(logoutURL.searchParams));
  const lr = formFields(out.body);
  assert.equal(lr.action, 'https://sp.example/slo');
  await assert.rejects(saml.validatePostResponseAsync({ SAMLResponse: lr.fields.SAMLResponse }), /InResponseTo is missing/, 'node-saml limitation, see comment');
  const lenient = nodeSaml(setup, { validateInResponseTo: 'ifPresent' });
  assert.equal((await lenient.validatePostResponseAsync({ SAMLResponse: lr.fields.SAMLResponse })).loggedOut, true);
});

test('SAML: after key rotation the old cert fails and fresh metadata works', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const before = await samlSetup(t);
  await api('POST', `/tenants/${t.id}/rotate-keys`);
  const old = nodeSaml(before);
  const f1 = formFields((await new Browser().get(await old.getAuthorizeUrlAsync('', undefined, {}))).body);
  await assert.rejects(old.validatePostResponseAsync({ SAMLResponse: f1.fields.SAMLResponse }), /signature/i);
  const ep = await api('GET', `/tenants/${t.id}/endpoints`);
  const fresh = nodeSaml({ app: before.app, cert: ep.certificatePem });
  const f2 = formFields((await new Browser().get(await fresh.getAuthorizeUrlAsync('', undefined, {}))).body);
  await fresh.validatePostResponseAsync({ SAMLResponse: f2.fields.SAMLResponse });
});

test('SAML: bad requests get a clear 400 page, never a 500 or a response', async () => {
  const t = await newTenant('okta');
  const { app } = await samlSetup(t);
  const garbage = await new Browser().get(app.ssoUrl + '?SAMLRequest=not-base64!!!');
  assert.equal(garbage.status, 400);
  const notXML = await new Browser().get(app.ssoUrl + '?SAMLRequest=' + encodeURIComponent(Buffer.from('hello').toString('base64')));
  assert.equal(notXML.status, 400);
  const stranger = new SAML({ entryPoint: app.ssoUrl, issuer: 'urn:someone-else', callbackUrl: 'https://evil.example/acs', idpCert: 'x', audience: false });
  const r = await new Browser().get(await stranger.getAuthorizeUrlAsync('', undefined, {}));
  assert.equal(r.status, 400);
  assert.match(r.body, /Unknown service provider/);
  assert.doesNotMatch(r.body, /evil\.example/, 'must never post to an ACS the app did not register');
});

// ---------- OIDC ----------

const REDIRECT = 'https://rp.example/cb';

async function oidcSetup(t, extra = {}, auth) {
  const app = await api('POST', `/tenants/${t.id}/apps`, { type: 'oidc', name: 'edge-rp', redirectUris: [REDIRECT], postLogoutRedirectUris: ['https://rp.example/bye'], ...extra });
  const config = await oidc.discovery(new URL(`${BASE}/t/${t.id}`), app.clientId, app.clientSecret, auth?.(app), { execute: [oidc.allowInsecureRequests] });
  return { app, config };
}

async function authorize(config, b, params = {}) {
  const verifier = oidc.randomPKCECodeVerifier(), state = oidc.randomState(), nonce = oidc.randomNonce();
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT, scope: 'openid profile email', state, nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256', ...params,
  });
  const res = await b.get(url.href);
  return { res, verifier, state, nonce };
}

test('OIDC: client_secret_post works, and a wrong secret is invalid_client', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const { config, app } = await oidcSetup(t, {}, a => oidc.ClientSecretPost(a.clientSecret));
  const a = await authorize(config, new Browser());
  const tok = await oidc.authorizationCodeGrant(config, new URL(a.res.location), { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce });
  assert.ok(tok.id_token);
  const bad = await oidc.discovery(new URL(`${BASE}/t/${t.id}`), app.clientId, undefined, oidc.ClientSecretPost('wrong'), { execute: [oidc.allowInsecureRequests] });
  const b2 = await authorize(bad, new Browser());
  await assert.rejects(oidc.authorizationCodeGrant(bad, new URL(b2.res.location), { pkceCodeVerifier: b2.verifier, expectedState: b2.state, expectedNonce: b2.nonce }),
    e => e.cause?.error === 'invalid_client');
});

test('OIDC: client credentials give an access token for the app, no ID token', async () => {
  const t = await newTenant('okta');
  const { config, app } = await oidcSetup(t);
  const tok = await oidc.clientCredentialsGrant(config, { scope: 'read:things' });
  assert.equal(tok.id_token, undefined);
  const claims = JSON.parse(Buffer.from(tok.access_token.split('.')[1], 'base64url'));
  assert.equal(claims.sub, app.clientId);
  assert.deepEqual(claims.scp, ['read:things'], 'Okta puts scopes in scp as a list');
});

test('OIDC: prompt=none fails with login_required, then succeeds once there is a session', async () => {
  const t = await newTenant('okta');
  const { config } = await oidcSetup(t);
  const b = new Browser();
  const silent = await authorize(config, b, { prompt: 'none' });
  assert.equal(new URL(silent.res.location).searchParams.get('error'), 'login_required');
  const a = await authorize(config, b);
  const done = await b.pickUser(await b.get(a.res.location), t.id, t.user('alice').id);
  assert.ok(done.location.startsWith(REDIRECT));
  const again = await authorize(config, b, { prompt: 'none' });
  const tok = await oidc.authorizationCodeGrant(config, new URL(again.res.location), { pkceCodeVerifier: again.verifier, expectedState: again.state, expectedNonce: again.nonce });
  assert.equal(tok.claims().sub, t.user('alice').id);
});

test('OIDC: response_mode=form_post', async () => {
  const t = await newTenant('google');
  await autoLogin(t, t.user('alice').userName);
  const { config } = await oidcSetup(t);
  const a = await authorize(config, new Browser(), { response_mode: 'form_post' });
  const { action, fields } = formFields(a.res.body);
  assert.equal(action, REDIRECT);
  const req = new Request(REDIRECT, { method: 'POST', body: new URLSearchParams(fields), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  const tok = await oidc.authorizationCodeGrant(config, req, { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce });
  assert.equal(tok.claims().hd, t.domain);
});

test('OIDC: implicit id_token flow (fragment)', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const { config } = await oidcSetup(t);
  oidc.useIdTokenResponseType(config);
  const nonce = oidc.randomNonce(), state = oidc.randomState();
  const res = await new Browser().get(oidc.buildAuthorizationUrl(config, { redirect_uri: REDIRECT, scope: 'openid email', nonce, state }).href);
  const url = new URL(res.location);
  assert.ok(url.hash.includes('id_token='), 'the ID token comes in the fragment');
  const claims = await oidc.implicitAuthentication(config, url, nonce, { expectedState: state });
  assert.equal(claims.email, t.user('alice').email);
});

test('OIDC: logout clears the IdP session and redirects only to registered URIs', async () => {
  const t = await newTenant('okta');
  const { config } = await oidcSetup(t);
  const b = new Browser();
  const a = await authorize(config, b);
  await b.pickUser(await b.get(a.res.location), t.id, t.user('alice').id);
  assert.ok(Object.keys(b.cookies).length, 'an IdP session cookie exists');
  const out = await b.get(oidc.buildEndSessionUrl(config, { post_logout_redirect_uri: 'https://rp.example/bye', state: 's1' }).href);
  assert.equal(out.location, 'https://rp.example/bye?state=s1');
  const silent = await authorize(config, b, { prompt: 'none' });
  assert.equal(new URL(silent.res.location).searchParams.get('error'), 'login_required', 'session is gone');
  const evil = await b.get(oidc.buildEndSessionUrl(config, { post_logout_redirect_uri: 'https://evil.example/' }).href);
  assert.equal(evil.status, 400);
  assert.equal(evil.location, null, 'no open redirect');
});

test('OIDC: codes work once, PKCE must match, unregistered redirect_uri never redirects', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const { config } = await oidcSetup(t);
  const a = await authorize(config, new Browser());
  const cb = new URL(a.res.location);
  await oidc.authorizationCodeGrant(config, cb, { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce });
  await assert.rejects(oidc.authorizationCodeGrant(config, cb, { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce }),
    e => e.cause?.error === 'invalid_grant', 'a code works once');
  const b = await authorize(config, new Browser());
  await assert.rejects(oidc.authorizationCodeGrant(config, new URL(b.res.location), { pkceCodeVerifier: oidc.randomPKCECodeVerifier(), expectedState: b.state, expectedNonce: b.nonce }),
    e => e.cause?.error === 'invalid_grant', 'wrong code_verifier');
  const evil = await authorize(config, new Browser(), { redirect_uri: 'https://evil.example/cb' });
  assert.equal(evil.res.status, 400);
  assert.equal(evil.res.location, null, 'must not redirect to an unregistered URI');
});

// openid-client caches the JWKS and refetches on an unknown kid only when the
// cache is at least 60 s old (oauth4webapi). So right after a rotation a
// long-lived client fails, and recovers within a minute. A fresh client works.
test('OIDC: openid-client right after a key rotation', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName);
  const { config, app } = await oidcSetup(t);
  oidc.enableNonRepudiationChecks(config);
  const run = async (cfg) => {
    const a = await authorize(cfg, new Browser());
    return oidc.authorizationCodeGrant(cfg, new URL(a.res.location), { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce });
  };
  await run(config);
  await api('POST', `/tenants/${t.id}/rotate-keys`);
  await assert.rejects(run(config), /no applicable keys/, 'cached JWKS younger than 60 s is not refetched');
  const fresh = await oidc.discovery(new URL(`${BASE}/t/${t.id}`), app.clientId, app.clientSecret, undefined, { execute: [oidc.allowInsecureRequests] });
  oidc.enableNonRepudiationChecks(fresh);
  await run(fresh);
});

test('Parallel sign-ins across tenants keep their simulations apart', async () => {
  const healthy = await newTenant('okta'), broken = await newTenant('entra');
  await autoLogin(healthy, healthy.user('alice').userName);
  await autoLogin(broken, broken.user('alice').userName, { oidcExpired: true });
  const [h, x] = [await oidcSetup(healthy), await oidcSetup(broken)];
  const one = async ({ config }) => {
    const a = await authorize(config, new Browser());
    return oidc.authorizationCodeGrant(config, new URL(a.res.location), { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce });
  };
  const results = await Promise.allSettled(Array.from({ length: 40 }, (_, i) => one(i % 2 ? x : h)));
  const ok = results.filter((r, i) => i % 2 === 0).every(r => r.status === 'fulfilled');
  const failed = results.filter((r, i) => i % 2 === 1).every(r => r.status === 'rejected');
  assert.ok(ok, 'every sign-in to the healthy tenant works');
  assert.ok(failed, 'every sign-in to the faulty tenant fails');
});

test('Latency simulation slows the IdP but sign-in still completes', async () => {
  const t = await newTenant('okta');
  await autoLogin(t, t.user('alice').userName, { latencyMs: 700 });
  const { config } = await oidcSetup(t); // discovery is delayed too
  const start = Date.now();
  const a = await authorize(config, new Browser());
  await oidc.authorizationCodeGrant(config, new URL(a.res.location), { pkceCodeVerifier: a.verifier, expectedState: a.state, expectedNonce: a.nonce });
  assert.ok(Date.now() - start >= 1400, 'authorize and token were both delayed');
});
