"""Bounded, quiet loopback WSGI transport for the development issuer.

Not a public production server. Socket timeouts bound idle I/O, not total
application execution time; a reverse proxy still needs its own request limits.
"""
import re
import threading
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler


class QuietHandler(WSGIRequestHandler):
    def parse_request(self):
        if not super().parse_request():
            return False
        hosts = self.headers.get_all('Host', [])
        lengths = self.headers.get_all('Content-Length', [])
        # Reject ambiguity before WSGI collapses duplicate headers. Do not
        # implement transfer decoding or accept obsolete folded field values.
        invalid = (len(hosts) != 1 or not hosts[0]
                   or any(c in hosts[0] for c in ', /\\')
                   or len(lengths) > 1
                   or self.headers.get_all('Transfer-Encoding') is not None
                   or any('\r' in value or '\n' in value
                          for _, value in self.headers.items()))
        if lengths and not re.fullmatch(r'[0-9]{1,6}', lengths[0]):
            invalid = True
        if invalid:
            self.send_error(400, 'Ambiguous request headers')
            return False
        if lengths and int(lengths[0]) > 65536:
            self.send_error(413, 'Request body too large')
            return False
        return True

    def log_message(self, *args):
        pass


class BoundedServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, address, handler=QuietHandler, *, workers=8, timeout=5):
        if type(workers) is not int or not 1 <= workers <= 32:
            raise ValueError('workers must be 1..32')
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError('timeout must be >0 and <=30 seconds')
        self.slots = threading.BoundedSemaphore(workers)
        self.io_timeout = timeout
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.io_timeout)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            # Never block the accept loop or create a worker for excess requests.
            try:
                request.setblocking(False)
                request.send(b'HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\nRetry-After: 1\r\nX-Codi-Admission: pre-dispatch\r\n\r\n')
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Avoid request bodies, credentials, or exception locals in stderr.
        pass
