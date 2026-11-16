import {FILE_PROTOCOL} from '@webos/runtime/file-protocol';
import {hash, signJws, inspectJws, verifyJws, sameKey, publicJwk, validateTimes, nowSeconds} from './crypto.mjs';
import {verifyIdentity, PROOF_TYPE} from './identity.mjs';
import {beginSession, logoutSession, renewSession, resumeSession} from './identity.mjs';
import {createSessionStore} from './session-store.mjs';

/** One account authority per runtime; only this closure holds session credentials. */
export function createAccountsClient({configUrl = '/config.json', persistSession = false} = {}) {
  if (typeof persistSession !== 'boolean') throw TypeError('Explicit browser sign-in retention setting required.');
  const url = new URL(configUrl, location.href);
  if (url.origin !== location.origin) throw Error('Same-origin account discovery is required.');
  let config, session = null, epoch = 0, phase = 'initializing', store, recordId = null,
    retention = persistSession ? 'empty' : 'disabled';
  const listeners = new Set();
  const inspect = () => Object.freeze({phase, epoch,
    accountId: session?.public.sub ?? null, sessionId: session?.public.sid ?? null,
    displayName: session?.public.name ?? null, expiresAt: session?.trust.claims?.exp ?? null,
    trust: session?.trust.level ?? null, retention});
  const notify = () => { const value = inspect(); for (const listener of listeners) { try { listener(value); } catch {} } };
  const ready = (async () => {
    try {
      const response = await fetch(url, {credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw Error('Account service unavailable.');
      const text = await response.text(); if (text.length > 65536) throw Error('Account discovery is too large.');
      config = JSON.parse(text);
      if (config?.identity?.mode !== 'server' || config.identity.issuer !== location.origin ||
          !Array.isArray(config.identity.authorityKeys) || !Array.isArray(config.accounts?.actions) ||
          !['register', 'signin'].every(action => config.accounts.actions.includes(action))) throw Error('Invalid authoritative account discovery.');
      if (persistSession) store = createSessionStore(config.identity.issuer + config.identity.apiBase);
      phase = 'signed-out'; notify();
    } catch (failure) { phase = 'failed'; notify(); throw failure; }
  })();
  ready.catch(() => {});
  function validRecord(record) {
    try { publicJwk(record?.identity?.key); } catch { return false; }
    return record?.version === 1 && typeof record.id === 'string' && record.id.length > 0 && record.id.length <= 64 &&
      typeof record.token === 'string' && /^[A-Za-z0-9_-]{32,128}$/.test(record.token) &&
      record.privateKey instanceof CryptoKey && !record.privateKey.extractable && record.privateKey.type === 'private' &&
      record.privateKey.algorithm.name === 'ECDSA' && record.privateKey.algorithm.namedCurve === 'P-256' &&
      record.privateKey.usages.includes('sign') && record.identity?.kind === 'registered' &&
      typeof record.identity.sid === 'string' && record.identity.sid.length <= 80 &&
      typeof record.identity.sub === 'string' && record.identity.sub.length <= 80 && record.identity.sub.startsWith('user:') &&
      typeof record.identity.name === 'string' && record.identity.name.length <= 64 &&
      typeof record.identity.certificate === 'string' && record.identity.certificate.length <= 16384;
  }
  async function removeRecord(id) {
    if (!store || id === null) return;
    try { await store.remove(id); retention = 'empty'; }
    catch { retention = 'unavailable'; throw Error('Could not forget this browser sign-in. Retry sign-out before closing.'); }
  }
  return Object.freeze({
    ready, inspect,
    async restore() {
      await ready;
      if (session || ['authenticating','restoring'].includes(phase)) throw Error('An account operation is already active.');
      if (!store) return null;
      const version = ++epoch; phase = 'restoring'; notify();
      let record;
      try { record = await store.read(); }
      catch { retention = 'unavailable'; phase = 'signed-out'; notify(); return null; }
      try {
        if (!record) { retention = 'empty'; return null; }
        if (!validRecord(record)) { await removeRecord(record.id); retention = 'invalid'; return null; }
        const next = await resumeSession(config, record);
        if (version !== epoch || (await store.read())?.id !== record.id) throw new DOMException('Remembered sign-in changed.', 'AbortError');
        session = next; recordId = record.id; retention = 'retained'; phase = 'authenticated'; notify(); return inspect();
      } catch (failure) {
        if (version !== epoch) throw failure;
        if ([401,403].includes(failure.status) || failure.invalidRetained) { await removeRecord(record.id); retention = failure.invalidRetained ? 'invalid' : 'expired'; return null; }
        // A timeout, offline browser or unavailable server must not erase the
        // credential or admit the cached identity as authenticated.
        throw failure;
      } finally { if (version === epoch && !session) { phase = 'signed-out'; notify(); } }
    },
    subscribe(listener) {
      if (typeof listener !== 'function') throw TypeError('Account listener required.');
      listeners.add(listener); return () => listeners.delete(listener);
    },
    async authenticate({mode, username, password}, {signal} = {}) {
      await ready;
      if (!['register', 'signin'].includes(mode)) throw Error('Choose sign in or register.');
      if (session || ['authenticating','restoring'].includes(phase)) throw Error('An account session or sign-in operation is already active.');
      if (signal?.aborted) throw new DOMException('Sign in cancelled.', 'AbortError');
      const attempt = ++epoch; phase = 'authenticating'; notify();
      try {
        const next = await beginSession(config, mode, username, password);
        if (next.public.kind !== 'registered' || next.public.name !== username.trim().toLowerCase()) {
          await logoutSession(config, next).catch(() => {}); throw Error('Account identity did not match.');
        }
        if (signal?.aborted || attempt !== epoch) {
          await logoutSession(config, next).catch(() => {}); throw new DOMException('Sign in cancelled.', 'AbortError');
        }
        if (store) {
          const id = crypto.randomUUID();
          try {
            await store.write({version:1,id,identity:next.public,privateKey:next.privateKey,token:next.token});
            recordId = id; retention = 'retained';
          } catch { retention = 'unavailable'; }
          if (signal?.aborted || attempt !== epoch) {
            await removeRecord(id).catch(() => {}); await logoutSession(config,next).catch(() => {});
            throw new DOMException('Sign in cancelled.', 'AbortError');
          }
        }
        session = next; phase = 'authenticated'; notify(); return inspect();
      } catch (failure) { if (attempt === epoch && !session) { phase = 'signed-out'; notify(); } throw failure; }
    },
    async logout() {
      await ready; const previous = session;
      // Forget locally before revocation; a failed network response cannot
      // cause the next refresh to restore the session the user ended.
      await removeRecord(recordId); recordId = null;
      ++epoch; session = null; phase = 'signed-out'; notify();
      if (!previous) return {status: 'signed-out'};
      try { await logoutSession(config, previous); return {status: 'signed-out'}; }
      catch { throw Object.assign(Error('Signed out on this device; server revocation could not be confirmed.'), {outcome: 'unknown'}); }
    },
    createFileAuthority() {
      if (!session || phase !== 'authenticated') throw Error('Sign in to access account files.');
      const bound = session, version = epoch, policy = config.identity;
      const basePath = config.gateway?.basePath;
      if (config.gateway?.version !== 'codi-user-files/1' || basePath !== policy.apiBase.slice(0, -7) + '/gateway') throw Error('Account files are unavailable.');
      const check = () => { if (session !== bound || epoch !== version || phase !== 'authenticated') throw new DOMException('Account changed.', 'AbortError'); };
      const post = async (path, body) => {
        check(); const response = await fetch(path, {method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
          headers: {'Content-Type': 'application/json', Authorization: 'Codi ' + bound.token}, body: JSON.stringify(body), signal: AbortSignal.timeout(10000)});
        const text = await response.text(); check(); if (text.length > 32768) throw Error('File authorization response too large.');
        let value;try { value = JSON.parse(text); } catch { throw Error('Invalid file authorization response.'); }
        if (!response.ok) throw Object.assign(Error(value.error || 'File authorization refused.'), {status: response.status});
        return value;
      };
      return Object.freeze({owner: bound.public.sub, sessionId: bound.public.sid, actorKind: 'human',
        publicKey: Object.freeze({...bound.public.key}), basePath, check,
        async authorize(nonce, requestSha) {
          check(); if (![nonce, requestSha].every(value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value))) throw Error('Bounded file authorization context required.');
          await verifyIdentity(bound.public, policy); check();
          const path = policy.apiBase + '/gateway/authorize';
          const challenge = await post(policy.apiBase + '/gateway/challenge', {key: bound.public.key, path});
          const request = JSON.stringify({nonce, request_sha256: requestSha}), now = nowSeconds();
          const proof = await signJws({v: 1, nonce: challenge.nonce, iss: bound.public.sid, aud: policy.issuer,
            method: 'POST', path, iat: now, exp: now + 60, request_sha256: await hash(request)}, bound.privateKey, PROOF_TYPE);
          const result = await post(path, {request, proof});
          const header = inspectJws(result.confirmation, FILE_PROTOCOL.confirmationType, 8192).header;
          const issuer = policy.authorityKeys.find(key => key.kid === header.kid); if (!issuer) throw Error('Unknown file authorization authority.');
          const grant = await verifyJws(result.confirmation, issuer.jwk, FILE_PROTOCOL.confirmationType, 8192); validateTimes(grant, FILE_PROTOCOL.grantLifetimeSeconds);
          const audience = location.origin + basePath;
          if (grant.v !== 1 || grant.iss !== policy.issuer || grant.aud !== audience || grant.sid !== bound.public.sid || grant.sub !== bound.public.sub || grant.kind !== 'registered' ||
              !sameKey(grant.cnf?.jwk, bound.public.key) || grant.nonce !== nonce || grant.request_sha256 !== requestSha) throw Error('File authorization binding changed.');
          check(); const use = await signJws({v: 1, iss: bound.public.sid, aud: audience, nonce,
            grant_sha256: await hash(result.confirmation), request_sha256: requestSha, method: 'POST', path: basePath + '/use', iat: grant.iat, exp: grant.exp}, bound.privateKey, FILE_PROTOCOL.useType);
          check(); return 'Codi-File ' + result.confirmation + ' ' + use;
        }
      });
    },
    async renew() {
      await ready; const previous = session, version = epoch;
      if (!previous) throw Error('Sign in is required.');
      await renewSession(config, previous);
      if (session !== previous || version !== epoch) throw new DOMException('Account changed.', 'AbortError');
      notify(); return inspect();
    }
  });
}
