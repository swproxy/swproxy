# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import http.client
import urllib.parse
import threading
import gzip
import time
import json
import re
import io
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE, STARTUPINFO, STARTF_USESHOWWINDOW
from collections import deque
from Crypto.Cipher import AES
from random import randint
import zlib, base64

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-s[-1]]


def _decrypt(msg, version=1):
    if version == 1:
        key = 'E2wN5Eo0t4gle92Z'
    elif version == 2:
        key = 'Gr4S2eiNl7zq5MrU'
    else:
        raise ValueError('Unknow Version')

    obj = AES.new(key.encode(), AES.MODE_CBC,
                  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'.encode())
    r = obj.decrypt(msg)

    return unpad(r)


def _encrypt(msg, version=1):
    if version == 1:
        key = 'E2wN5Eo0t4gle92Z'
    elif version == 2:
        key = 'Gr4S2eiNl7zq5MrU'
    else:
        raise ValueError('Unknow Version')

    msg = pad(msg)
    obj = AES.new(key.encode(), AES.MODE_CBC,
                  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'.encode())
    r = obj.encrypt(msg.encode())
    return r


def decrypt_request(msg, version=2):
    return _decrypt(base64.b64decode(msg), version)


def encrypt_request(msg, version=2):
    return base64.b64encode(_encrypt(msg, version))


def decrypt_response(msg, version=2):
    return zlib.decompress(_decrypt(base64.b64decode(msg), version))


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs\\')

    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def end_headers(self):
        if not hasattr(self, '_headers_buffer'):
            self._headers_buffer = []
        super(ProxyRequestHandler, self).end_headers()

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

    def log_message(self, format, *args):
        return
        # self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(
                self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s\\%s.crt" % (self.certdir.rstrip('\\'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                startupinfo = STARTUPINFO()
                startupinfo.dwFlags |= STARTF_USESHOWWINDOW

                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE,
                           startupinfo=startupinfo)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey,
                            "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE,
                           startupinfo=startupinfo)
                p2.communicate()

        self.wfile.write("{} {} {}\r\n".format(self.protocol_version, 200, 'Connection Established').encode())
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://cert/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urllib.parse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("{} {} {}\r\n".format(self.protocol_version, res.status, res.reason).encode())

        self.wfile.write(str(res.headers).strip().replace('\n', '\r\n').encode() + b'\r\n')
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("{} {} {}\r\n".format(self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = (
            'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
            'transfer-encoding',
            'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            data = gzip.compress(text)
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            text = gzip.decompress(data)
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("{} {} {}\r\n".format(self.protocol_version, 200, 'OK').encode())
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        # self.print_info(req, req_body, res, res_body)
        pass


class SWHandler(ProxyRequestHandler):
    # _headers_buffer = []
    replaced_urls = deque(maxlen=1024)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        if 'gateway_c2.php' in req.path:
            try:
                j = json.loads(decrypt_response(res_body))

                if j['command'] == 'HubUserLogin' and j['ret_code'] == 0:
                    winfo = j['wizard_info']
                    fname = '{}-{}.json'.format(winfo['wizard_name'], winfo['wizard_id'])

                    print('Exported to {}'.format(fname))

                    with open(fname, 'wb') as f:
                        f.write(json.dumps(j).encode())
            except Exception as e:
                pass
        return res_body


def run_proxy(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1", ip='0.0.0.0',
              port=8899):
    print('Welcome to Summoners War Proxy 0.1!')
    print('Yet another exporter!')
    print('Author: @swproxy(https://github.com/swproxy)\n\n')

    if os.path.isdir('certs'):
        for file in os.listdir('certs'):
            os.unlink('certs\\' + file)
    else:
        os.mkdir('certs')
    server_address = (ip, port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print("Serving proxy on", sa[0], "port", sa[1], "...")
    print('1. Set proxy on your phone\n'
          '2. Open http://cert/ with default browser(Safari on iOS, haven\'t test on android)\n'
          '3. Install certificate(Important!)\n'
          '4. Restart game\n'
          'Note: Step 2 and 3 only needed once.\n')

    httpd.serve_forever()


if __name__ == '__main__':

    sys.stderr = io.BytesIO()

    port = randint(1024, 65535)
    fail = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    while fail < 3:
        try:
            s.connect(('1.1.1.1', 80))
            ip = s.getsockname()[0]
            break
        except socket.timeout:
            s.close()
            fail += 1
        except socket.error:
            s.close()
            ip = '0.0.0.0'
            break
    if fail >= 3:
        ip = '0.0.0.0'
    s.close()
    run_proxy(SWHandler, ip=ip, port=port)
