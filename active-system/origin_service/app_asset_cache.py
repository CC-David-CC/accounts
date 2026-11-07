"""HTTP caching for registered, immutable public software only.

The trusted staged catalog supplies identity hashes. This does not replace
release verification, authorize a request, or cache visitor/account/file data.
No asset body is hashed or buffered by this policy.
"""
import json
import re
import stat
from pathlib import Path
from types import MappingProxyType

CACHE_CONTROL = 'private, max-age=31536000, immutable'
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_FILES = 16384
# Trusted installed software inventory; unrelated to visitor file/transfer quotas.
MAX_APP_BYTES = 512 * 1024 * 1024
MAX_ASSET_BYTES = 256 * 1024 * 1024
SHA = re.compile(r'[a-f0-9]{64}')
APP = re.compile(r'[a-z][a-z0-9-]{0,31}')
FILE = re.compile(r'(?:[A-Za-z0-9_@+-][A-Za-z0-9_@+.-]*/)*[A-Za-z0-9_@+-][A-Za-z0-9_@+.-]*')


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate app metadata')
        result[key] = value
    return result


def invalid_constant(_):
    raise ValueError('Non-JSON app metadata')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class RegisteredAppAssetCache:
    def __init__(self, public_root):
        self.root = Path(public_root)
        # Missing/invalid catalogs disable this optimization. Existing serving
        # and authorization still decide the response; never infer registration
        # merely from a hash-looking URL.
        try:
            records = self._capture()
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            records = {}
        self.records = MappingProxyType(records)

    def _capture(self):
        catalog = self.root / 'assets/desktop/apps.json'
        cursor = self.root
        for part in ('assets', 'desktop', 'apps.json'):
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError('Regular app catalog required')
        if catalog.is_symlink() or catalog.stat().st_size > MAX_CATALOG_BYTES:
            raise ValueError('Bounded regular app catalog required')
        raw = catalog.read_bytes()
        if len(raw) > MAX_CATALOG_BYTES:
            raise ValueError('App catalog exceeds limit')
        data = json.loads(raw, object_pairs_hook=unique_pairs,
                          parse_constant=invalid_constant)
        if (type(data) is not dict or data.get('version') != 'codi-public-apps/2'
                or type(data.get('hostAPI')) is not int or data['hostAPI'] != 2
                or type(data.get('apps')) is not list or len(data['apps']) > 128):
            raise ValueError('Registered public app metadata required')
        result, app_ids, files = {}, set(), 0
        for app in data['apps']:
            if type(app) is not dict or not isinstance(app.get('id'), str) or not APP.fullmatch(app['id']):
                raise ValueError('Invalid app identity')
            app_id, bundle = app['id'], app.get('bundleSHA256')
            prefix = 'assets/desktop/apps/' + app_id + '/' + str(bundle) + '/'
            entries = app.get('files')
            if (app_id in app_ids or app.get('kind') != 'browser'
                    or not isinstance(bundle, str) or not SHA.fullmatch(bundle)
                    or app.get('path') != prefix + 'index.mjs'
                    or type(entries) is not dict or not 1 <= len(entries) <= 4096):
                raise ValueError('Invalid versioned app registration')
            app_ids.add(app_id)
            total_bytes = 0
            for name, record in entries.items():
                files += 1
                if (files > MAX_FILES or not isinstance(name, str)
                        or len(prefix + name) > 4096 or not FILE.fullmatch(name)
                        or any(p in ('.', '..') for p in name.split('/'))
                        or type(record) is not dict or set(record) != {'sha256', 'bytes'}
                        or not isinstance(record['sha256'], str) or not SHA.fullmatch(record['sha256'])
                        or type(record['bytes']) is not int or not 0 <= record['bytes'] <= MAX_ASSET_BYTES):
                    raise ValueError('Invalid app asset registration')
                total_bytes += record['bytes']
                if total_bytes > MAX_APP_BYTES:
                    raise ValueError('App bundle exceeds limit')
                target = self.root / (prefix + name)
                try:
                    info = target.stat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_size != record['bytes']:
                    continue
                result['/' + prefix + name] = (target, identity(info), record['sha256'])
            entry = entries.get('index.mjs')
            if (not entry or app.get('sha256') != entry['sha256']
                    or type(app.get('bytes')) is not int
                    or app.get('bytes') != entry['bytes']):
                raise ValueError('App entry differs from registration')
        return result

    def response_headers(self, path, status, headers, method='GET'):
        record = self.records.get(path)
        if method not in ('GET', 'HEAD') or status != '200 OK' or record is None:
            return headers
        names = {name.lower() for name, _ in headers}
        if names & {'set-cookie', 'www-authenticate'}:
            return headers
        try:
            if identity(record[0].stat()) != record[1]:
                return headers
        except OSError:
            return headers
        result = [(name, value) for name, value in headers if name.lower() != 'cache-control']
        result.append(('Cache-Control', CACHE_CONTROL))
        if 'etag' not in names:
            result.append(('ETag', '"sha256-' + record[2] + '"'))
        return result
