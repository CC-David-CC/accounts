import {hash, inspectJws, nowSeconds, requireThat, sameKey, signJws, validateTimes, verifyJws} from './crypto.mjs';
import {PROOF_TYPE, verifyIdentity} from './identity.mjs';

const GRANT_TYPE = 'codi-guest-network-identity+jwt';
const WIRE_PROOF_TYPE = 'codi-guest-network-use+jws';
const CHALLENGE_TYPE = 'codi-guest-network-challenge/1';
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

async function readResponse(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let text = '', size = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireThat(size <= 16384, 'Guest authorization response is too large.');
      text += decoder.decode(value, {stream: true});
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  return JSON.parse(text + decoder.decode());
}

/** Only the Accounts closure can turn a live session into proofs for a specific wire. */
export function guestNetworkAuthority(config, session, check) {
  const {identity, guestNetwork: network} = config;
  if (network?.previewPolicy?.version !== 'codi-guest-egress-policy/3') return null;
  const {apiBase, issuer} = identity;
  requireThat(identity.mode === 'server' && issuer === location.origin && typeof apiBase === 'string' &&
    apiBase.length <= 135 && /^\/(?:[A-Za-z0-9_-]+\/)*api\/v1$/.test(apiBase), 'Same-origin guest identity service required.');
  const base = apiBase.slice(0, -7);
  const relayPath = base + '/guest-network';
  const {authorization} = network;
  requireThat(network.relayPath === relayPath && authorization?.version === 'codi-guest-network-auth/1' &&
    typeof authorization.policySHA256 === 'string' && /^[a-f0-9]{64}$/.test(authorization.policySHA256),
    'Pinned guest network policy required.');
  const policyHash = authorization.policySHA256;
  const api = apiBase + '/guest-network';

  async function operation(name, body, cancellation) {
    const deadline = AbortSignal.timeout(10000);
    const signal = cancellation ? AbortSignal.any([deadline, cancellation]) : deadline;
    const verifySession = () => { check(); signal.throwIfAborted(); };
    const post = async (path, body, authorized) => {
      verifySession();
      const response = await fetch(path, {
        method: 'POST', mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
        headers: {'Content-Type': 'application/json', ...(authorized ? {Authorization: 'Codi ' + session.token} : {})},
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        await response.body?.cancel();
        throw Object.assign(Error('Guest network authorization was refused.'), {status: response.status});
      }
      const result = await readResponse(response);
      verifySession();
      return result;
    };
    verifySession();
    await verifyIdentity(session.public, identity);
    const path = api + '/' + name;
    const challenge = await post(api + '/challenge', {path, key: session.public.key}, false);
    const iat = nowSeconds();
    requireThat(exact(challenge, ['nonce', 'expires_at']) && identifier(challenge.nonce) &&
      Number.isSafeInteger(challenge.expires_at) && iat < challenge.expires_at && challenge.expires_at <= iat + 65,
      'Invalid guest issuer challenge.');
    const request = JSON.stringify(body);
    const proof = await signJws({v: 1, nonce: challenge.nonce, iss: session.public.sid, aud: issuer,
      method: 'POST', path, iat, exp: iat + 60, request_sha256: await hash(request)}, session.privateKey, PROOF_TYPE);
    return post(path, {request, proof}, true);
  }

  return Object.freeze({
    relayPath, policyHash, check,
    async status({signal} = {}) {
      try {
        const result = await operation('status', {policy_sha256: policyHash}, signal);
        requireThat(exact(result, ['policy_sha256', 'expires_at']) && result.policy_sha256 === policyHash &&
          Number.isSafeInteger(result.expires_at) && result.expires_at > nowSeconds(), 'Invalid guest network eligibility.');
        return result.expires_at;
      } catch (error) {
        if (error.status === 403) { check(); signal?.throwIfAborted(); return null; }
        throw error;
      }
    },
    async connect(challenge, {signal} = {}) {
      const now = nowSeconds();
      requireThat(exact(challenge, ['type', 'nonce', 'connection_id', 'policy_sha256', 'expires_at']) &&
        challenge.type === CHALLENGE_TYPE && challenge.policy_sha256 === policyHash &&
        identifier(challenge.nonce) && identifier(challenge.connection_id) &&
        Number.isSafeInteger(challenge.expires_at) && now < challenge.expires_at && challenge.expires_at <= now + 35,
        'Invalid guest wire challenge.');
      const {nonce, connection_id} = challenge;
      const result = await operation('authorize', {nonce, connection_id, policy_sha256: policyHash}, signal);
      requireThat(exact(result, ['grant', 'expires_at']), 'Invalid guest issuer response.');
      const {grant} = result;
      const {header} = inspectJws(grant, GRANT_TYPE, 8192);
      const trusted = identity.authorityKeys.find(key => key.kid === header.kid);
      requireThat(trusted, 'Unknown guest network authority.');
      const claims = await verifyJws(grant, trusted.jwk, GRANT_TYPE, 8192);
      validateTimes(claims, 30);
      const aud = issuer + relayPath;
      const {sid, sub, key} = session.public;
      requireThat(exact(claims, ['v','iss','aud','sub','sid','kind','cnf','iat','exp','jti','nonce',
        'connection_id','policy_sha256','session_deadline']) && claims.v === 1 && claims.iss === issuer &&
        claims.aud === aud && claims.sid === sid && claims.sub === sub && claims.kind === 'registered' &&
        exact(claims.cnf, ['jwk']) && sameKey(claims.cnf.jwk, key) && identifier(claims.jti) &&
        claims.nonce === nonce && claims.connection_id === connection_id && claims.policy_sha256 === policyHash &&
        claims.exp === result.expires_at && Number.isSafeInteger(claims.session_deadline) &&
        claims.session_deadline >= claims.exp, 'Guest wire grant binding changed.');
      const proof = await signJws({v: 1, iss: sid, aud, nonce, connection_id, policy_sha256: policyHash,
        grant_sha256: await hash(grant), method: 'CONNECT', path: relayPath, iat: claims.iat, exp: claims.exp},
        session.privateKey, WIRE_PROOF_TYPE);
      check();
      signal?.throwIfAborted();
      return Object.freeze({grant, proof, expiresAt: claims.exp});
    },
  });
}
