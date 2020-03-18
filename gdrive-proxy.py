from functools import partial
from html.parser import HTMLParser
from http.client import HTTPResponse, IncompleteRead
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.error import URLError
import urllib.request
import socketserver
import logging
import re

log = logging.getLogger()


class ConfirmPageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.download_path = None

    def handle_tag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id') == 'uc-download-link':
            self.download_path = attrs.get('href')

    def handle_starttag(self, tag, attrs):
        self.handle_tag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self.handle_tag(tag, attrs)


class GDriveSession:
    root = "https://docs.google.com"
    download_path = "/uc?export=download&id=%s"

    def __init__(self, cookiejar=None, timeout=5, debug=False, user_agent=None):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(debuglevel=(1 if debug else 0)),
            urllib.request.HTTPCookieProcessor(cookiejar=cookiejar))
        self.timeout = timeout
        self.user_agent = user_agent

    def urlopen(self, request: Request) -> HTTPResponse:
        return self.opener.open(request, timeout=self.timeout)

    def open_file(self, id_, headers=None) -> HTTPResponse:
        if headers is None:
            headers = {}
        if self.user_agent:
            # override user-agent
            headers = dict((key, val) for key, val in headers.items()
                           if key.lower() != 'user-agent')
            headers['User-Agent'] = self.user_agent

        download_url = self.root + (self.download_path % id_)
        request = Request(download_url, headers=headers)
        response = self.urlopen(request)

        if response.status in [200, 206] and \
                'Content-Disposition' not in response.msg and \
                'text/html' in response.getheader('Content-Type', ''):
            # confirm page?? parse it!
            parser = ConfirmPageParser()
            parser.feed(response.read().decode('utf-8'))
            response.close()
            new_download_url = self.root + parser.download_path
            return self.urlopen(Request(new_download_url, headers=headers))
        else:
            # pass as is
            return response


def sanitize_headers(headers: list) -> list:
    to_remove = ['transfer-encoding', 'content-length', 'connection', 'server',
                 'host', 'cookie', 'set-cookie']
    return list((key, val) for key, val in headers
                if key.lower() not in to_remove)


def response_length(resp: HTTPResponse):
    """In case of chunked encoding, calc length from content-range. TODO"""
    headers = dict((key.lower(), val) for key, val in resp.getheaders())
    if resp.getcode() == 206 and 'content-range' in headers:
        match = re.match(r' *bytes *(\d+) *- *(\d+)', headers['content-range'])
        if match is None:
            raise RuntimeError("unexpected content-range: %s" %
                               headers['content-range'])
        start_byte, end_byte = match.groups()
        return int(end_byte) - int(start_byte) + 1
    else:
        return resp.length


class ChunkedEncoder:
    def __init__(self, delegate):
        self.delegate = delegate

    def write(self, data: bytes):
        # TODO may need buffering
        self.delegate.write(str('%X' % len(data)).encode('ascii') + b'\r\n')
        self.delegate.write(data)
        self.delegate.write(b'\r\n')

    def finish(self):
        self.delegate.write(b'0\r\n\r\n')


# noinspection PyAttributeOutsideInit
class GDriveProxyRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    read_size = 16 * 1024  # 16KiB
    log = logging.getLogger('RequestHandler')

    def __init__(self, gdrive: GDriveSession, request, client_address, server):
        self.gdrive = gdrive
        super().__init__(request, client_address, server)

    def log_message(self, format, *args):
        self.log.info("%s:%d -- %s", *self.client_address, format%args)

    def log_error(self, format, *args):
        self.log.error("%s:%d -- %s", *self.client_address, format%args)

    def log_exception(self, format, *args):
        self.log.exception("%s:%d -- %s", *self.client_address, format%args)

    def relay(self, upstream: HTTPResponse):
        # add upstream response headers after sanitization
        headers = sanitize_headers(upstream.getheaders())

        # transport level headers
        total_length = response_length(upstream)
        down_stream = self.wfile
        if total_length is None:
            headers.append(('Transfer-Encoding', 'chunked'))
            down_stream = ChunkedEncoder(self.wfile)
        else:
            headers.append(('Content-Length', str(total_length)))

        # send headers
        self.log_message("got upstream response. relaying to client...")
        if upstream.getcode() == 206 and 'Range' not in self.headers:
            # translate 206 -> 200 if the downstream is not a range request
            self.send_response(200)
        else:
            self.send_response(upstream.getcode())
        for key, val in headers:
            self.send_header(key, val)
        self.end_headers()

        # relay data
        while True:
            # read
            try:
                data = upstream.read(self.read_size)
            except (TimeoutError, IncompleteRead) as e:
                self.log_error("upstream closed prematurely: %s" % e)
                self.close_connection = True
                break
            if len(data) == 0:  # EOF
                if isinstance(down_stream, ChunkedEncoder):
                    down_stream.finish()
                break

            # send
            try:
                down_stream.write(data)
            except ConnectionError as e:
                self.log_error("client closed prematurely: %s" % e.strerror)
                self.close_connection = True
                break
        self.log_message("done!")

    def do_GET(self):
        args = self.path.split('/')
        if len(args) < 2:
            self.log_error("invalid request path: %s" % self.path)
            self.send_error(304)
            return
        args = args[1:]
        self.log_message("got request for id=%s. passing to upstream...", args[0])

        # upstream request
        upstream_headers = dict(sanitize_headers(self.headers.items()))
        if 'Range' not in self.headers:
            # always do range requests to parse content-range header
            upstream_headers['Range'] = 'bytes=0-'

        # NOTE when handling DOWNSTREAM error, set .close_connection!
        try:
            upstream_response = self.gdrive.open_file(args[0],
                                                      headers=upstream_headers)
        except (TimeoutError, ConnectionError, URLError) as e:
            self.log_error("error communicating with gdrive: %s" % e)
            self.send_error(504, 'Upstream GDrive Not Available')
            return
        except:
            self.log_exception("while opening gdrive resource")
            self.send_error(500, "Internal Server Error")
            return

        with upstream_response:
            self.relay(upstream_response)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', type=int, default=8989, help="server port")
    parser.add_argument('--address', '-a', default='localhost', help="server address")
    parser.add_argument('--timeout', '-t', type=int, default=5, help="socket timeout")
    parser.add_argument('--user-agent', help="override user-agent string")
    parser.add_argument('--debug', '-d', action='store_true', help="print http headers")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    gdrive = GDriveSession(timeout=args.timeout, debug=args.debug, user_agent=args.user_agent)
    request_handler = partial(GDriveProxyRequestHandler, gdrive)
    address = (args.address, args.port)
    with ThreadingHTTPServer(address, request_handler) as server:
        log.info("bound to address %s! serving requests...", address)
        server.serve_forever()

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))

# TODO use logging module; override .log(), .log_error()
# TODO implement GDriveSession.timeout
#