import {makeKey, publicJwk, sameKey, thumbprint, signJws, verifyJws, inspectJws, hash, requireThat, nowSeconds, validateTimes} from './crypto.mjs';
export const CERT_TYPE='codi-identity+jwt';
export const PROOF_TYPE='codi-request+jws';
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
  let data; try { data=await r.json(); } catch { if(!r.ok)throw Object.assign(new Error('Service request failed ('+r.status+')'),{status:r.status,preDispatch:r.status===503&&r.headers.get('X-Codi-Admission')==='pre-dispatch'});throw new Error('Invalid service response'); }
  if(!r.ok) throw Object.assign(new Error(data.error || 'Service request failed ('+r.status+')'),{status:r.status});
  return data;
}
export async function authenticatedRequest(policy, session, path, data) {
  requireThat(policy.mode==='server'&&typeof policy.apiBase==='string'&&policy.apiBase.length<=135&&/^\/(?:[A-Za-z0-9_-]+\/)*api\/v1$/.test(policy.apiBase),'Same-origin identity service is required');
  requireThat(['anonymous','auth','renew','logout'].some(route=>path===policy.apiBase+'/'+route),'Wrong authenticated API path');
  requireThat(data&&typeof data==='object'&&!Array.isArray(data)&&!Object.hasOwn(data,'ice_preference'),'Reserved ICE preference request field');
  const request=JSON.stringify(data); // The signed request bytes are sent unchanged.
  const retrySignin=path===policy.apiBase+'/auth'&&data.operation==='signin';
  const retryRegisterAdmission=path===policy.apiBase+'/auth'&&data.operation==='register';
  for(let attempt=0;;attempt++){
    let submitted=false;
    try{
      // Every attempt obtains a new single-use challenge and signs it anew.
      const ch=await requestJson(policy.apiBase+'/challenge',{key:session.public.key,path});
      const t=nowSeconds();
      const proof=await signJws({v:1,nonce:ch.nonce,iss:session.public.sid,
        aud:policy.issuer,method:'POST',path,iat:t,exp:t+60,request_sha256:await hash(request)},session.privateKey,PROOF_TYPE);
      submitted=true;return await requestJson(path,{request,proof},session.token);
    }catch(error){
      const busy=[502,503,504].includes(error.status)||(error.status===429&&/^(Password service busy|Account (?:database|admission) busy)/.test(error.message));
      // These exact 429s are emitted only before account work or a transaction
      // begins. A transport error may follow a committed registration.
      const registrationAdmissionBusy=retryRegisterAdmission&&submitted&&error.status===429&&['Password service busy; try again shortly','Account admission busy; try again shortly'].includes(error.message);
      const registrationBeforeDispatch=retryRegisterAdmission&&submitted&&error.status===503&&error.preDispatch===true;
      // A challenge failure also precedes submission, so gateway errors at
      // that stage cannot have created an account.
      const registrationChallengeBusy=retryRegisterAdmission&&!submitted&&[502,503,504].includes(error.status);
      if((!(retrySignin&&busy)&&!registrationAdmissionBusy&&!registrationBeforeDispatch&&!registrationChallengeBusy)||attempt>=19)throw error;
      await new Promise(resolve=>setTimeout(resolve,300+Math.random()*Math.min(1500,300+attempt*150)));
    }
  }
}
export async function beginSession(config, mode, name='', password='') {
  const policy=config.identity;
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
    session.public=result.identity;session.token=result.session_token;
  }
  session.trust=await verifyIdentity(session.public,policy);
  session.fingerprint=await thumbprint(session.public.key);
  return session;
}
export async function renewSession(config, session) {
  const result=await authenticatedRequest(config.identity,session,config.identity.apiBase+'/renew',{});
  requireIdentityBinding(session.public,result.identity);
  const trust=await verifyIdentity(result.identity,config.identity);
  session.public=result.identity; session.trust=trust;
}
export async function logoutSession(config,session) {
  if(config.identity.mode==='server') await authenticatedRequest(config.identity,session,config.identity.apiBase+'/logout',{});
}
