// Encrypted assertions and signed AuthnRequests, checked by node-saml: it
// decrypts what mock-idp encrypts, and mock-idp verifies what it signs.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SAML } from '@node-saml/node-saml';
import { api, formFields, Browser, newTenant } from './helpers.mjs';

// keypair makes an SP key and self-signed certificate, as an app would.
function keypair(cn) {
  const dir = mkdtempSync(join(tmpdir(), 'sp-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'),
    '-days', '2', '-subj', `/CN=${cn}`], { stdio: 'ignore' });
  return { key: readFileSync(join(dir, 'k.pem'), 'utf8'), cert: readFileSync(join(dir, 'c.pem'), 'utf8') };
}

const sp = keypair('interop-sp'), stranger = keypair('someone-else');
const matrix = [];
after(() => { console.log('\nnode-saml decryption matrix'); console.table(matrix); });

async function setup(appFields) {
  const t = await newTenant('okta');
  await api('PATCH', `/tenants/${t.id}/simulations`, { autoLogin: t.user('alice').userName });
  await api('POST', `/tenants/${t.id}/apps`, {
    type: 'saml', name: 'crypto-sp', entityId: 'urn:crypto:sp', acsUrl: 'https://sp.example/acs',
    encryptAssertion: true, spEncryptionCert: sp.cert, spSigningCert: sp.cert, requireSignedRequests: true, ...appFields,
  });
  const ep = await api('GET', `/tenants/${t.id}/endpoints`);
  return { t, app: ep.apps.find(a => a.spEntityId === 'urn:crypto:sp'), idpCert: ep.certificatePem };
}

function nodeSaml({ app, idpCert }, opts = {}) {
  return new SAML({
    entryPoint: app.ssoUrl, issuer: app.spEntityId, callbackUrl: app.acsUrl, audience: app.spEntityId,
    idpCert, idpIssuer: app.idpEntityId, wantAssertionsSigned: true, wantAuthnResponseSigned: false,
    validateInResponseTo: 'always', identifierFormat: null,
    decryptionPvk: sp.key, privateKey: sp.key, signatureAlgorithm: 'sha256', ...opts,
  });
}

async function viaRedirect(saml) {
  const r = await new Browser().get(await saml.getAuthorizeUrlAsync('', undefined, {}));
  if (r.status !== 200 || !r.body.includes('SAMLResponse')) throw new Error(`IdP answered ${r.status}: ${r.body.match(/class="err">([^<]+)/)?.[1] || ''}`);
  return saml.validatePostResponseAsync({ SAMLResponse: formFields(r.body).fields.SAMLResponse });
}

for (const alg of ['aes128-cbc', 'aes256-cbc', 'aes128-gcm', 'aes256-gcm']) {
  for (const kt of ['rsa-oaep', 'rsa-1_5']) {
    test(`node-saml decrypts ${alg} + ${kt}, mock-idp verifies the signed request`, async () => {
      const s = await setup({ encryptionAlg: alg, keyTransportAlg: kt });
      let outcome;
      try {
        const { profile } = await viaRedirect(nodeSaml(s));
        assert.equal(profile.nameID, s.t.user('alice').userName);
        outcome = 'decrypted';
      } catch (e) { outcome = 'refused: ' + e.message.slice(0, 70); }
      matrix.push({ alg, keyTransport: kt, 'node-saml': outcome });
      if (kt === 'rsa-oaep') assert.equal(outcome, 'decrypted'); // RSA 1.5 is legacy; node-saml may refuse it, recorded only
    });
  }
}

test('node-saml signs the AuthnRequest by HTTP-POST; mock-idp verifies the XML signature', async () => {
  const s = await setup({});
  const saml = nodeSaml(s, { authnRequestBinding: 'HTTP-POST' });
  const form = formFields(await saml.getAuthorizeFormAsync('', undefined, {}));
  const r = await new Browser().post(s.app.ssoUrl, form.fields);
  assert.equal(r.status, 200, r.body.match(/class="err">([^<]+)/)?.[1]);
  const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: formFields(r.body).fields.SAMLResponse });
  assert.equal(profile.nameID, s.t.user('alice').userName);
});

test('a request signed with a key the app does not trust is refused, in both bindings', async () => {
  const s = await setup({});
  const r1 = await new Browser().get(await nodeSaml(s, { privateKey: stranger.key }).getAuthorizeUrlAsync('', undefined, {}));
  assert.equal(r1.status, 400);
  assert.match(r1.body, /HTTP-Redirect binding\) is invalid/);
  const post = nodeSaml(s, { privateKey: stranger.key, authnRequestBinding: 'HTTP-POST' });
  const r2 = await new Browser().post(s.app.ssoUrl, formFields(await post.getAuthorizeFormAsync('', undefined, {})).fields);
  assert.equal(r2.status, 400);
  assert.match(r2.body, /HTTP-POST binding\) is invalid/);
});

test('an unsigned request is refused when the app requires signing', async () => {
  const s = await setup({});
  const r = await new Browser().get(await nodeSaml(s, { privateKey: undefined }).getAuthorizeUrlAsync('', undefined, {}));
  assert.equal(r.status, 400);
  assert.match(r.body, /requires signed AuthnRequests/);
});

test('node-saml with the wrong decryption key cannot read the assertion', async () => {
  const s = await setup({});
  await assert.rejects(viaRedirect(nodeSaml(s, { decryptionPvk: stranger.key })));
});

test('encryption faults reach node-saml', async () => {
  const s = await setup({});
  for (const sim of ['samlWrongEncryptionKey', 'samlBadSignature', 'samlSignatureWrapping']) {
    await api('PATCH', `/tenants/${s.t.id}/simulations`, { [sim]: true, once: true });
    await assert.rejects(viaRedirect(nodeSaml(s)), undefined, `${sim} was accepted`);
  }
});
