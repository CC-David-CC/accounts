import {makeKey, publicJwk, sameKey, thumbprint, signJws, verifyJws, inspectJws, hash, requireThat, nowSeconds, validateTimes} from './crypto.mjs';
export const CERT_TYPE='codi-identity+jwt';
export const PROOF_TYPE='codi-request+jws';
const requestPreferences=new WeakMap();
export function icePreference(config){
  const preference=config.rtc?.preference;
  if(preference===undefined)return null;
  requireThat(config.rtc.credentialMode==='session-turn/1'&&config.rtc.iceTransportPolicy==='relay'&&preference&&Object.keys(preference).length===3&&['version','allowed','preferred'].every(k=>Object.hasOwn(preference,k))&&preference.version==='codi-session-ice/1','Unsupported ICE preference capability');
  requireThat(Array.isArray(preference.allowed)&&['["relay"]','["relay","all"]'].includes(JSON.stringify(preference.allowed))&&preference.allowed.includes(preference.preferred),'Invalid operator ICE preference');
  return {version:preference.version,transport:preference.preferred};
}
export function bindRequestPreference(config){
  const preference=icePreference(config);
  requestPreferences.set(config.identity,preference?Object.freeze(preference):null);
}
export async function verifyIdentity(identity, policy, now=nowSeconds()) {
  requireThat(identity && typeof identity.sid==='string' && identity.sid.length<=80,'Invalid session id');
  requireThat(typeof identity.name==='string' && identity.name.length<=64,'Invalid display name');
  publicJwk(identity.key);
  if(identity.certificate===null) {
    requireThat(policy.mode==='local-development','Official certificate required; no silent downgrade');
    requireThat(identity.kind==='anonymous' && identity.sub===identity.sid,'Only local anonymous sessions are supported without authority');
    return {level:'local',label:'Local / not server validated',claims:null};
  }
  requireThat(policy.mode==='server' && typeof identity.certificate==='string','Certificate not accepted by this profile');
  const raw=inspectJws(identity.certificate,CERT_TYPE,16384);
  const trusted=policy.authorityKeys.find(k=>k.kid===raw.header.kid);
  requireThat(trusted,'Unknown authority key: never trust a key supplied by a peer');
  const c=await verifyJws(identity.certificate,trusted.jwk,CERT_TYPE,16384);
  validateTimes(c,900,now);
  requireThat(c.v===1 && c.iss===policy.issuer && c.aud===policy.audience,'Wrong certificate issuer/audience/version');
  requireThat(c.sid===identity.sid && c.sub===identity.sub && c.name===identity.name && c.kind===identity.kind,'Identity claims mismatch');
  requireThat(['anonymous','registered'].includes(c.kind) && typeof c.jti==='string','Invalid certificate claims');
  requireThat(c.cnf && sameKey(c.cnf.jwk,identity.key),'Certificate is bound to another key');
  return {level:policy.authorityClass==='official'?'official':'test-server',
    label:policy.authorityClass==='official'?'Official server validated':'Test server validated',claims:c};
}
/** Renewal changes authority proof only; never the session/account/key binding. */
export function requireIdentityBinding(previous,next) {
  requireThat(next&&Object.keys(next).length===6&&['sid','sub','name','kind','key','certificate'].every(k=>Object.hasOwn(next,k)),'Public identity fields required');
  requireThat(new TextEncoder().encode(JSON.stringify(next)).length<=20000,'Identity proof too large');
  requireThat(['sid','sub','name','kind'].every(k=>previous[k]===next[k])&&sameKey(previous.key,next.key),'Renewal changed identity binding');
}
export async function verifyRenewedIdentity(previous,next,policy) {
  requireIdentityBinding(previous,next);
  requireThat(policy.mode==='server'&&typeof previous.certificate==='string'&&typeof next.certificate==='string','Certificate renewal requires a server identity');
  const oldTrust=await verifyIdentity(previous,policy),trust=await verifyIdentity(next,policy);
  requireThat(oldTrust.claims.exp>nowSeconds()&&trust.claims.exp>nowSeconds(),'Certificate expired during renewal verification');
  requireThat(trust.claims.exp>oldTrust.claims.exp&&trust.claims.iat>=oldTrust.claims.iat,'Certificate renewal must advance authority expiry');
  return trust;
}
async function requestJson(path, body, token=null) {
  const r=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json',...(token?{Authorization:'Codi '+token}:{})},body:JSON.stringify(body),cache:'no-store',signal:AbortSignal.timeout(10000)});
  let data; try { data=await r.json(); } catch { throw new Error('Invalid service response'); }
  if(!r.ok) throw Object.assign(new Error(data.error || 'Service request failed ('+r.status+')'),{status:r.status});
  return data;
}
export async function authenticatedRequest(policy, session, path, data) {
  requireThat(policy.mode==='server'&&typeof policy.apiBase==='string'&&policy.apiBase.length<=135&&/^\/(?:[A-Za-z0-9_-]+\/)*api\/v1$/.test(policy.apiBase),'Same-origin identity service is required');
  requireThat(['anonymous','auth','renew','logout'].some(route=>path===policy.apiBase+'/'+route),'Wrong authenticated API path');
  requireThat(data&&typeof data==='object'&&!Array.isArray(data)&&!Object.hasOwn(data,'ice_preference'),'Reserved ICE preference request field');
  const preference=requestPreferences.get(policy);
  const request=JSON.stringify(preference&&!path.endsWith('/logout')?{...data,ice_preference:preference}:data); // Exact signed bytes are sent unchanged.
  const ch=await requestJson(policy.apiBase+'/challenge',{key:session.public.key,path});
  const t=nowSeconds();
  const proof=await signJws({v:1,nonce:ch.nonce,iss:session.public.sid,
    aud:policy.issuer,method:'POST',path,iat:t,exp:t+60,request_sha256:await hash(request)},session.privateKey,PROOF_TYPE);
  return requestJson(path,{request,proof},session.token);
}
export function sessionTurnConfig(config,result,trust){
  if(config.rtc?.credentialMode===undefined)return null;
  requireThat(config.identity.mode==='server'&&config.rtc.credentialMode==='session-turn/1','Unsupported session ICE policy');
  const rtc=result.rtc,now=nowSeconds();
  const transport=icePreference(config)?.transport??(config.rtc.iceTransportPolicy===undefined?'relay':config.rtc.iceTransportPolicy);
  requireThat(['all','relay'].includes(transport)&&rtc&&Object.keys(rtc).length===3&&rtc.iceTransportPolicy===transport&&Number.isSafeInteger(rtc.expiresAt)&&rtc.expiresAt>now&&rtc.expiresAt<=now+600&&rtc.expiresAt<=trust.claims.exp,'Invalid TURN credential lifetime or transport policy');
  requireThat(Array.isArray(config.rtc.turnUrls)&&config.rtc.turnUrls.length>=1&&config.rtc.turnUrls.length<=4&&Array.isArray(rtc.iceServers)&&rtc.iceServers.length===1,'Invalid TURN endpoints');
  const server=rtc.iceServers[0];
  requireThat(server&&Object.keys(server).length===4&&JSON.stringify(server.urls)===JSON.stringify(config.rtc.turnUrls)&&server.credentialType==='password','TURN endpoint or credential profile changed');
  requireThat(typeof server.username==='string'&&server.username.startsWith(rtc.expiresAt+':')&&server.username.length<=128&&typeof server.credential==='string'&&/^[A-Za-z0-9+/]{27}=$/.test(server.credential),'Invalid TURN credential');
  return JSON.parse(JSON.stringify(rtc));
}
export async function beginSession(config, mode, name='', password='') {
  const policy=config.identity;
  bindRequestPreference(config);
  requireThat(isSecureContext && crypto.subtle,'A secure context (localhost or HTTPS) is required');
  const key=await makeKey(); const sid=crypto.randomUUID();
  const session={privateKey:key.privateKey,public:{sid,sub:sid,name:'anon-'+sid.slice(0,8),kind:'anonymous',key:key.publicKey,certificate:null},trust:null};
  if(policy.mode==='local-development') {
    requireThat(mode==='anonymous','SIGNIN requires the real identity service; no local namespace is created');
    if(name.trim()) session.public.name=name.trim().slice(0,64);
  } else {
    requireThat(policy.mode==='server','Unknown identity configuration');
    const path=policy.apiBase+(mode==='anonymous'?'/anonymous':'/auth');
    const data=mode==='anonymous'?{}:{username:name,password};
    const result=await authenticatedRequest(policy,session,path,data);
    requireThat(sameKey(result.identity.key,session.public.key),'Server changed the session key');
    const trust=await verifyIdentity(result.identity,policy);
    session.rtc=sessionTurnConfig(config,result,trust);
    session.public=result.identity;session.token=result.session_token;
  }
  session.trust=await verifyIdentity(session.public,policy);
  session.fingerprint=await thumbprint(session.public.key);
  return session;
}
export async function renewSession(config, session) {
  bindRequestPreference(config);
  const result=await authenticatedRequest(config.identity,session,config.identity.apiBase+'/renew',{});
  requireIdentityBinding(session.public,result.identity);
  const trust=await verifyIdentity(result.identity,config.identity);
  const rtc=sessionTurnConfig(config,result,trust);
  session.public=result.identity; session.trust=trust;session.rtc=rtc;
}
export async function logoutSession(config,session) {
  if(config.identity.mode==='server') await authenticatedRequest(config.identity,session,config.identity.apiBase+'/logout',{});
}
