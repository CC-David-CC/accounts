"""Proof-bound, short-lived operation delegation owned by Accounts.

Consumers must enforce the returned scope against actual component resource
metadata. Its grants cannot replace agent file authorization.
"""
import copy
import math
import re
import secrets
import uuid
from urllib.parse import urlsplit

from . import jose
from .service import Failure

CHALLENGE = '/api/v1/agents/challenge'
CREATE = '/api/v1/agents/create'
LIST = '/api/v1/agents/list'
REVOKE = '/api/v1/agents/revoke'
AUTHORIZE = '/api/v1/agents/authorize'
CONSUME = '/api/v1/agents/consume'
PATHS = frozenset((CREATE, LIST, REVOKE, AUTHORIZE, CONSUME))
GRANT_TYPE = 'webos-agent-operation+jwt'
MAX_TRANSPORT_BYTES = 262144


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise Failure(400, 'Exact operation fields required')


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('Canonical identifier required')
    return value


def resource_ids(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise Failure(400, 'Bounded exact resource list required')
    for value in values:
        if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
            raise Failure(400, 'Exact resource identifiers required')
    if len(set(values)) != len(values):
        raise Failure(400, 'Duplicate resource identifier')
    return list(values)


def scope_value(value, owner_sid):
    exact(value, ('desktopId', 'sessionId', 'instanceId', 'resources', 'commands'))
    identifier(value['desktopId']); identifier(value['instanceId'])
    if value['sessionId'] != owner_sid:
        raise Failure(403, 'Delegation must target the approving account session')
    resources = resource_ids(value['resources'])
    if 'view:' + value['instanceId'] not in resources:
        raise Failure(400, 'Explicit view resource required')
    commands = value['commands']
    if not isinstance(commands, list) or not 1 <= len(commands) <= 32 or any(not isinstance(c, str) or not re.fullmatch(r'[a-z][A-Za-z0-9_.-]{0,95}', c) for c in commands) or len(set(commands)) != len(commands):
        raise Failure(400, 'Bounded exact command list required')
    return copy.deepcopy({**value, 'resources': resources})


def intent_value(raw, scope):
    if not isinstance(raw, str) or not 0 < len(raw.encode('utf-8')) <= 65536:
        raise Failure(400, 'Bounded operation intent required')
    value = jose.loads(raw)
    # Reject nonfinite exponents and integers that a browser would round.
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is int and abs(item) > 9007199254740991 or type(item) is float and not math.isfinite(item):
            raise Failure(400, 'Interoperable finite operation numbers required')
        if isinstance(item, dict): pending.extend(item.values())
        elif isinstance(item, list): pending.extend(item)
    if not isinstance(value, dict) or value.get('method') not in ('application.inspect', 'application.execute'):
        raise Failure(400, 'Known live operation method required')
    execute = value['method'] == 'application.execute'
    exact(value, ('method', 'target', 'resources', 'request') if execute else ('method', 'target', 'resources'))
    target = value['target']
    exact(target, ('desktopId', 'sessionId', 'instanceId', 'resourceId'))
    if any(target[k] != scope[k] for k in ('desktopId', 'sessionId', 'instanceId')) or target['resourceId'] != 'view:' + scope['instanceId']:
        raise Failure(403, 'Operation target outside delegation')
    resources = resource_ids(value['resources'])
    if target['resourceId'] not in resources or not set(resources) <= set(scope['resources']):
        raise Failure(403, 'Operation resources outside delegation')
    command = 'view.inspect'
    if execute:
        request = value['request']
        if not isinstance(request, dict) or request.get('instanceId') != scope['instanceId'] or request.get('sessionId') != scope['sessionId']:
            raise Failure(403, 'Nested application target outside delegation')
        names = set(request) & {'operation', 'command'}
        if len(names) != 1 or not isinstance(request[next(iter(names))], str):
            raise Failure(400, 'Unambiguous application command required')
        command = request[next(iter(names))]
    if command not in scope['commands']:
        raise Failure(403, 'Operation command outside delegation')
    return value


class Delegations:
    """RAM-only delegations; restart invalidates all credentials and grants.

    Owner account/session liveness is checked at issuance and again at consume.
    A grant is consumed before dispatch, never inferred from UI visibility.
    No human session secret or private signing key is copied into a delegation.
    """
    def __init__(self, issuer, *, capacity=128, grant_capacity=1024):
        if not callable(getattr(issuer, 'session_binding', None)):
            raise ValueError('Retained Accounts session policy required')
        if type(capacity) is not int or type(grant_capacity) is not int or not 1 <= capacity <= 1024 or not 1 <= grant_capacity <= 4096:
            raise ValueError('Bounded delegation capacity required')
        self.issuer = issuer
        self.capacity = capacity
        self.grant_capacity = grant_capacity
        self.records = {}
        self.grants = {}
        self.audience = issuer.c.origin + issuer.base_path + '/desktop/operations'

    def _cleanup(self):
        issuer = self.issuer; issuer.cleanup(); now = issuer.now()
        self.records = {digest: r for digest, r in self.records.items() if r['expires_at'] > now and r['owner_digest'] in issuer.sessions}
        ids = {r['id'] for r in self.records.values()}
        self.grants = {key: r for key, r in self.grants.items() if r['expires_at'] > now and r['delegation_id'] in ids}

    def challenge(self, data):
        exact(data, ('key', 'path'))
        if data['path'] not in {self.issuer.base_path + p for p in PATHS}:
            raise Failure(400, 'Known delegation proof path required')
        key = jose.public_jwk(jose.load_public(data['key']))
        with self.issuer.lock:
            self._cleanup()
            if len(self.issuer.challenges) >= self.issuer.c.max_challenges:
                raise Failure(429, 'Challenge capacity reached')
            nonce = secrets.token_urlsafe(32); expires = self.issuer.now() + 60
            self.issuer.challenges[nonce] = {'key': key, 'path': data['path'], 'expires': expires}
            return {'nonce': nonce, 'expires_at': expires}

    def _owner(self, key, proof, authorization):
        if not isinstance(authorization, str) or not authorization.startswith('Codi '):
            raise Failure(401, 'Owner session authentication required')
        checked = self.issuer.continue_session({}, key, proof, '/api/v1/renew', authorization)
        if checked['identity']['kind'] != 'registered':
            raise Failure(403, 'Registered owner required')
        return checked['identity'], jose.digest(authorization[5:])

    def _binding(self, record):
        return self.issuer.session_binding(record['owner_digest'], record['owner_sub'], record['owner_sid'])

    def _public(self, record):
        return {'id': record['id'], 'scope': copy.deepcopy(record['scope']), 'expires_at': record['expires_at'],
                'owner_session_id': record['owner_sid'], 'agent_key_thumbprint': jose.thumbprint(record['key'])}

    def dispatch(self, path, envelope, authorization):
        """Verify a one-use caller proof before invoking any policy operation.

        HTTP adapters must additionally enforce origin, method, body limits and
        admission budgets. No such adapter is installed by this core module.
        """
        if path not in PATHS:
            raise Failure(404, 'Unknown delegation operation')
        try:
            if not isinstance(envelope, dict) or not isinstance(envelope.get('request'), str) or len(envelope['request'].encode('utf-8')) > MAX_TRANSPORT_BYTES:
                raise Failure(400, 'Bounded delegation envelope required')
            data, key, proof = self.issuer.consume_proof(envelope, path)
            with self.issuer.lock:
                self._cleanup()
                if path == AUTHORIZE:
                    return self._authorize(data, key, proof, authorization)
                owner, digest = self._owner(key, proof, authorization)
                if path == CREATE:
                    exact(data, ('agent_key', 'scope', 'seconds'))
                    if type(data['seconds']) is not int or not 1 <= data['seconds'] <= 900:
                        raise Failure(400, 'Delegation lifetime must be 1..900 seconds')
                    if len(self.records) >= self.capacity:
                        raise Failure(429, 'Delegation capacity reached')
                    agent_key = jose.public_jwk(jose.load_public(data['agent_key']))
                    scope = scope_value(data['scope'], owner['sid'])
                    binding = self.issuer.session_binding(digest, owner['sub'], owner['sid'])
                    token = secrets.token_urlsafe(32)
                    record = {'id': str(uuid.uuid4()), 'key': agent_key, 'scope': scope,
                              'owner_sub': owner['sub'], 'owner_sid': owner['sid'], 'owner_digest': digest,
                              'expires_at': min(self.issuer.now() + data['seconds'], binding['deadline'])}
                    if record['expires_at'] <= self.issuer.now(): raise Failure(401, 'Owner session expired')
                    self.records[jose.digest(token)] = record
                    return {**self._public(record), 'agent_token': token}
                if path == LIST:
                    exact(data, ())
                    result = []
                    for record in self.records.values():
                        if record['owner_sub'] != owner['sub']: continue
                        try: self._binding(record)
                        except Failure as error:
                            if error.status == 401: continue
                            raise
                        result.append(self._public(record))
                    return {'delegations': result}
                if path == REVOKE:
                    exact(data, ('id',)); identifier(data['id'])
                    matches = [r for r in self.records.values() if r['id'] == data['id'] and r['owner_sub'] == owner['sub']]
                    if not matches: raise Failure(404, 'Delegation unavailable')
                    self.records = {k: r for k, r in self.records.items() if r['id'] != data['id']}
                    self._cleanup()
                    return {'revoked': True}
                return self._consume(data, owner)
        except Failure:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise Failure(400, 'Invalid delegation request') from None

    def _authorize(self, data, key, proof, authorization):
        exact(data, ('intent',))
        if not isinstance(authorization, str) or not authorization.startswith('Agent ') or len(authorization) > 128:
            raise Failure(401, 'Agent credential required')
        record = self.records.get(jose.digest(authorization[6:]))
        if record is None or proof.get('iss') != record['id'] or jose.thumbprint(key) != jose.thumbprint(record['key']):
            raise Failure(401, 'Invalid agent binding')
        binding = self._binding(record)
        intent_value(data['intent'], record['scope'])
        if len(self.grants) >= self.grant_capacity:
            raise Failure(429, 'Operation grant capacity reached')
        now = self.issuer.now(); expires = min(now + 30, record['expires_at'], binding['deadline']); grant_id = secrets.token_urlsafe(32)
        if expires <= now: raise Failure(401, 'Delegation expired')
        claims = {'v': 1, 'iss': self.issuer.c.origin, 'aud': self.audience, 'sub': record['owner_sub'],
                  'sid': record['owner_sid'], 'agent_id': record['id'], 'cnf': {'jwk': record['key']},
                  'iat': now, 'exp': expires, 'jti': grant_id, 'intent_sha256': jose.digest(data['intent'])}
        confirmation = jose.sign(claims, self.issuer.key, GRANT_TYPE, self.issuer.kid)
        self.grants[grant_id] = {'delegation_id': record['id'], 'intent_sha256': claims['intent_sha256'], 'expires_at': expires}
        return {'confirmation': confirmation, 'expires_at': expires}

    def _consume(self, data, owner):
        exact(data, ('confirmation', 'intent'))
        claims = jose.verify(data['confirmation'], self.issuer.jwk, GRANT_TYPE, 8192)
        fields = {'v', 'iss', 'aud', 'sub', 'sid', 'agent_id', 'cnf', 'iat', 'exp', 'jti', 'intent_sha256'}
        if set(claims) != fields or type(claims['v']) is not int or claims['v'] != 1 or claims['iss'] != self.issuer.c.origin or claims['aud'] != self.audience:
            raise Failure(401, 'Invalid operation grant context')
        now = self.issuer.now()
        if type(claims['iat']) is not int or type(claims['exp']) is not int or not claims['iat'] <= now < claims['exp'] or not 0 < claims['exp'] - claims['iat'] <= 30:
            raise Failure(401, 'Operation grant expired')
        if claims['sub'] != owner['sub'] or claims['sid'] != owner['sid']:
            raise Failure(403, 'Operation grant belongs to another owner session')
        pending = self.grants.get(claims['jti'])
        record = next((r for r in self.records.values() if r['id'] == claims['agent_id']), None)
        if pending is None or record is None or pending['delegation_id'] != record['id'] or pending['expires_at'] != claims['exp'] or claims['cnf'] != {'jwk': record['key']}:
            raise Failure(401, 'Operation grant unavailable or already consumed')
        self._binding(record)
        intent = intent_value(data['intent'], record['scope'])
        digest = jose.digest(data['intent'])
        if digest != claims['intent_sha256'] or digest != pending['intent_sha256']:
            raise Failure(403, 'Authorized operation intent changed')
        if claims['exp'] <= self.issuer.now(): raise Failure(401, 'Operation grant expired')
        del self.grants[claims['jti']]
        return {'actor': {'kind': 'agent', 'id': record['id'], 'accountId': record['owner_sub'], 'sessionId': record['owner_sid']},
                'scope': copy.deepcopy(record['scope']), 'intent': intent, 'expires_at': claims['exp']}


class DelegationAuthority:
    """HTTP boundary for operation grants. Desktop owns application dispatch."""

    def __init__(self, issuer, application=None):
        self.issuer = issuer
        self.application = issuer if application is None else application
        self.delegations = Delegations(issuer)

    def __call__(self, env, start):
        path = env.get('PATH_INFO', '/')
        if path != CHALLENGE and path not in PATHS:
            return self.application(env, start)
        issuer = self.issuer
        try:
            if env.get('HTTP_HOST') != urlsplit(issuer.c.origin).netloc or env.get('HTTP_ORIGIN') != issuer.c.origin:
                raise Failure(403, 'Unexpected operation origin')
            if env.get('REQUEST_METHOD') != 'POST':
                raise Failure(405, 'POST required')
            if env.get('QUERY_STRING') or env.get('HTTP_TRANSFER_ENCODING') or env.get('HTTP_CONTENT_ENCODING'):
                raise Failure(400, 'Plain JSON request without query or transfer encoding required')
            if env.get('CONTENT_TYPE', '').split(';')[0].strip() != 'application/json':
                raise Failure(415, 'JSON required')
            length = env.get('CONTENT_LENGTH', '')
            if not length.isascii() or not length.isdecimal() or len(length) > 6 or not 0 < int(length) <= MAX_TRANSPORT_BYTES:
                raise Failure(413, 'Bounded operation request required')
            issuer.throttle('agent-transport-peer:' + env.get('REMOTE_ADDR', 'unknown'))
            issuer.throttle('agent-transport-global', limit=20 * issuer.c.rate_per_minute)
            raw = env['wsgi.input'].read(int(length))
            if len(raw) != int(length):
                raise Failure(400, 'Truncated operation request')
            request = jose.loads(raw)
            if path == CHALLENGE:
                result = self.delegations.challenge(request)
            else:
                result = self.delegations.dispatch(path, request, env.get('HTTP_AUTHORIZATION', ''))
            return issuer.json_response(start, 200, result)
        except Failure as error:
            return issuer.json_response(start, error.status, {'error': error.message})
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            return issuer.json_response(start, 400, {'error': 'Invalid operation request'})
        except Exception:
            return issuer.json_response(start, 500, {'error': 'Operation authorization unavailable'})
