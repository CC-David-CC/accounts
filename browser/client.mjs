import {beginSession, logoutSession, renewSession} from './identity.mjs';

/** One account authority per runtime; only this closure holds session credentials. */
export function createAccountsClient({configUrl = '/config.json'} = {}) {
  const url = new URL(configUrl, location.href);
  if (url.origin !== location.origin) throw Error('Same-origin account discovery is required.');
  let config, session = null, epoch = 0, phase = 'initializing';
  const listeners = new Set();
  const inspect = () => Object.freeze({phase, epoch,
    accountId: session?.public.sub ?? null, sessionId: session?.public.sid ?? null,
    displayName: session?.public.name ?? null, expiresAt: session?.trust.claims?.exp ?? null,
    trust: session?.trust.level ?? null});
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
      phase = 'signed-out'; notify();
    } catch (failure) { phase = 'failed'; notify(); throw failure; }
  })();
  ready.catch(() => {});
  return Object.freeze({
    ready, inspect,
    subscribe(listener) {
      if (typeof listener !== 'function') throw TypeError('Account listener required.');
      listeners.add(listener); return () => listeners.delete(listener);
    },
    async authenticate({mode, username, password}, {signal} = {}) {
      await ready;
      if (!['register', 'signin'].includes(mode)) throw Error('Choose sign in or register.');
      if (session || phase === 'authenticating') throw Error('An account session or sign-in operation is already active.');
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
        session = next; phase = 'authenticated'; notify(); return inspect();
      } catch (failure) { if (attempt === epoch && !session) { phase = 'signed-out'; notify(); } throw failure; }
    },
    async logout() {
      await ready; const previous = session; ++epoch; session = null; phase = 'signed-out'; notify();
      if (!previous) return {status: 'signed-out'};
      try { await logoutSession(config, previous); return {status: 'signed-out'}; }
      catch { throw Object.assign(Error('Signed out on this device; server revocation could not be confirmed.'), {outcome: 'unknown'}); }
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
