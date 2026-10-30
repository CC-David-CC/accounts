import {strictJson} from './strict-json.mjs';
/** Narrow ES256 JWS profile, not a general JOSE implementation.
 * Standard cryptographic primitives are provided by Web Crypto, never JS math.
 * Sign the transmitted base64url bytes; never reserialize received signed JSON.
 */
export const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', {fatal: true});
export const nowSeconds = () => Math.floor(Date.now() / 1000);
export function requireThat(ok, message) { if (!ok) throw new Error(message); }
export function b64(bytes) {
  const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = ''; for (const v of a) s += String.fromCharCode(v);
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
export function unb64(text) {
  requireThat(typeof text === 'string' && /^[A-Za-z0-9_-]+$/.test(text), 'Invalid base64url');
  const s = atob(text.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4-text.length%4)%4));
  const out = Uint8Array.from(s, c=>c.charCodeAt(0));
  requireThat(b64(out) === text, 'Noncanonical base64url');
  return out;
}
export async function hash(text) { return b64(await crypto.subtle.digest('SHA-256', enc.encode(text))); }
export function publicJwk(jwk) {
  requireThat(jwk && jwk.kty === 'EC' && jwk.crv === 'P-256' && !('d' in jwk), 'P-256 public key required');
  requireThat(unb64(jwk.x).length === 32 && unb64(jwk.y).length === 32, 'Invalid EC coordinates');
  return {kty:'EC', crv:'P-256', x:jwk.x, y:jwk.y};
}
export function sameKey(a,b) {
  const x=publicJwk(a), y=publicJwk(b); return x.x===y.x && x.y===y.y;
}
// RFC 7638 member order for an EC JWK thumbprint.
export async function thumbprint(jwk) {
  const p=publicJwk(jwk); return hash(JSON.stringify({crv:p.crv,kty:p.kty,x:p.x,y:p.y}));
}
export async function makeKey() {
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  return {privateKey:pair.privateKey, publicKey:publicJwk(await crypto.subtle.exportKey('jwk',pair.publicKey))};
}
export function inspectJws(token, expectedType, maxBytes=262144) {
  requireThat(typeof token==='string' && token.length<=maxBytes, 'Signed object is too large');
  const parts=token.split('.'); requireThat(parts.length===3, 'Three JWS parts required');
  const header=strictJson(dec.decode(unb64(parts[0])) );
  requireThat(header && header.alg==='ES256' && header.typ===expectedType, 'Wrong JWS algorithm or type');
  requireThat(Object.keys(header).every(k=>['alg','typ','kid'].includes(k)), 'Unsupported JWS header');
  const signature=unb64(parts[2]); requireThat(signature.length===64,'ES256 requires raw r||s, 64 bytes');
  const payload=strictJson(dec.decode(unb64(parts[1])));
  requireThat(payload && typeof payload==='object' && !Array.isArray(payload),'Object payload required');
  return {header,payload,signature,bytes:enc.encode(parts[0]+'.'+parts[1])};
}
export async function signJws(payload, key, typ) {
  const data=b64(enc.encode(JSON.stringify({alg:'ES256',typ})))+'.'+b64(enc.encode(JSON.stringify(payload)));
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,enc.encode(data));
  return data+'.'+b64(sig);
}
export async function verifyJws(token,jwk,typ,maxBytes) {
  const p=inspectJws(token,typ,maxBytes);
  const key=await crypto.subtle.importKey('jwk',publicJwk(jwk),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  requireThat(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,p.signature,p.bytes),'Signature verification failed');
  return p.payload;
}
export function validateTimes(p, maxLifetime, now=nowSeconds()) {
  for(const k of ['iat','exp']) requireThat(Number.isSafeInteger(p[k]),'Integer '+k+' required');
  requireThat(p.iat<=now+30 && p.exp>now && p.exp>p.iat && p.exp-p.iat<=maxLifetime,'Expired or invalid time window');
  if('nbf' in p) requireThat(Number.isSafeInteger(p.nbf) && p.nbf<=now+30 && p.nbf<=p.exp,'Invalid nbf');
}
