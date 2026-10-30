"""Restricted ES256 compact JWS profile using the cryptography library.
Not a general JOSE library. Untrusted alg/kid values never select code or URLs.
"""
import base64
import hashlib
import json
import re
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
class Invalid(ValueError): pass

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
def unb64(text: str) -> bytes:
    if not isinstance(text,str) or not re.fullmatch(r'[A-Za-z0-9_-]+',text): raise Invalid('base64url')
    try: raw=base64.urlsafe_b64decode(text+'='*((-len(text))%4))
    except Exception as e: raise Invalid('base64url') from e
    if b64(raw)!=text: raise Invalid('noncanonical base64url')
    return raw

def dumps(obj) -> str:
    return json.dumps(obj,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def _unique(pairs):
    result={}
    for k,v in pairs:
        if k in result: raise Invalid('duplicate JSON key')
        result[k]=v
    return result
def loads(text):
    return json.loads(text,object_pairs_hook=_unique,parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite JSON')))
def digest(text: str) -> str:
    return b64(hashlib.sha256(text.encode('utf-8')).digest())
def public_jwk(key) -> dict:
    if isinstance(key,ec.EllipticCurvePrivateKey): key=key.public_key()
    n=key.public_numbers()
    return {'kty':'EC','crv':'P-256','x':b64(n.x.to_bytes(32,'big')),'y':b64(n.y.to_bytes(32,'big'))}
def load_public(jwk):
    if not isinstance(jwk,dict) or jwk.get('kty')!='EC' or jwk.get('crv')!='P-256' or 'd' in jwk: raise Invalid('public P-256 key required')
    x,y=unb64(jwk.get('x')),unb64(jwk.get('y'))
    if len(x)!=32 or len(y)!=32: raise Invalid('EC coordinate length')
    try:return ec.EllipticCurvePublicNumbers(int.from_bytes(x,'big'),int.from_bytes(y,'big'),ec.SECP256R1()).public_key()
    except ValueError as e:raise Invalid('invalid curve point') from e

def thumbprint(jwk):
    p=public_jwk(load_public(jwk))
    return digest(dumps({'crv':p['crv'],'kty':p['kty'],'x':p['x'],'y':p['y']}))
def sign(payload,key,typ,kid=None):
    header={'alg':'ES256','typ':typ}
    if kid is not None:header['kid']=kid
    message=b64(dumps(header).encode())+'.'+b64(dumps(payload).encode())
    der=key.sign(message.encode('ascii'),ec.ECDSA(hashes.SHA256()))
    r,s=utils.decode_dss_signature(der)
    return message+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
def inspect(token,typ,limit=65536):
    if not isinstance(token,str) or len(token)>limit:raise Invalid('JWS size')
    parts=token.split('.')
    if len(parts)!=3:raise Invalid('JWS parts')
    try:header,payload=loads(unb64(parts[0])),loads(unb64(parts[1]))
    except (ValueError,UnicodeError,TypeError) as e:raise Invalid('JWS JSON') from e
    if not isinstance(header,dict) or header.get('alg')!='ES256' or header.get('typ')!=typ or not set(header)<= {'alg','typ','kid'}:raise Invalid('JWS header')
    sig=unb64(parts[2])
    if len(sig)!=64 or not isinstance(payload,dict):raise Invalid('JWS shape')
    return header,payload,sig,(parts[0]+'.'+parts[1]).encode('ascii')
def verify(token,jwk,typ,limit=65536):
    _,payload,sig,message=inspect(token,typ,limit)
    der=utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big'))
    try:load_public(jwk).verify(der,message,ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:raise Invalid('signature') from e
    return payload
