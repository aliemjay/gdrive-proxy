#!/usr/bin/env python3

# Copyright (c) 2020 Ali MJ Al-Nasrawy

import argparse
import logging
import os.path
import re
import socket
import socketserver
import urllib.request
from functools import partial
from html.parser import HTMLParser
from http.client import HTTPResponse, IncompleteRead
from http.cookiejar import MozillaCookieJar
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Lock
from urllib.error import URLError
from urllib.request import Request

log = logging.getLogger()


class ConfirmPageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.is_error = True
        self.error_msg = ""
        self.download_path = None
        self._expect_error_msg = False

    def handle_tag(self, tag, attrs, is_startend=False):
        attrs = dict(attrs)
        if attrs.get('id') == 'uc-download-link':
            self.is_error = False
            self.download_path = attrs.get('href')
        elif not is_startend and attrs.get('id') in \
                ['uc-error-caption', 'uc-error-subcaption']:
            self.is_error = True
            self._expect_error_msg = True

    def handle_starttag(self, tag, attrs):
        self.handle_tag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self.handle_tag(tag, attrs, is_startend=True)

    def handle_data(self, data):
        if self._expect_error_msg:
            self._expect_error_msg = False
            self.error_msg += data + " "


class GDriveError(Exception):
    pass


class GDriveSession:
    root = "https://docs.google.com"
    download_path = "/uc?export=download&id=%s"

    def __init__(self, cookiejar=None, timeout=5, debug=False, user_agent=None):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(debuglevel=(1 if debug else 0)),
            urllib.request.HTTPCookieProcessor(cookiejar=cookiejar))
        self.timeout = timeout
        self.user_agent = user_agent
        self.lock = Lock()
        self.cache = {}

    def urlopen(self, request: Request) -> HTTPResponse:
        return self.opener.open(request, timeout=self.timeout)

    def _open_file(self, id_, headers=None) -> HTTPResponse:
        download_url = self.root + (self.download_path % id_)
        request = Request(download_url, headers=headers)
        response = self.urlopen(request)

        if 'Content-Disposition' not in response.msg and \
                'text/html' in response.getheader('Content-Type', ''):
            # confirm page?? parse it!
            parser = ConfirmPageParser()
            with response:
                parser.feed(response.read().decode('utf-8'))
            parser.close()
            if parser.is_error:
                raise GDriveError("couldn't bypass webpage %s. "
                                  "got this message: %s" %
                                  (download_url, parser.error_msg))

            new_download_url = self.root + parser.download_path
            log.debug("following url from confirm page: %s" % new_download_url)
            response = self.urlopen(Request(new_download_url, headers=headers))

        return response

    def open_file(self, id_, headers=None):
        if headers is None:
            headers = {}
        if self.user_agent:
            # override user-agent
            headers = dict((key, val) for key, val in headers.items()
                           if key.lower() != 'user-agent')
            headers['User-Agent'] = self.user_agent

        # serialize to avoid spamming and protect cache
        with self.lock:
            if id_ in self.cache:
                # use cache
                log.debug("trying cached url %s for %s", self.cache[id_], id_)
                request = Request(self.cache[id_], headers=headers)
                try:
                    response = self.urlopen(request)
                except URLError:
                    pass
                else:
                    log.info("cached url success %s", id_)
                    return response

            response = self._open_file(id_, headers)
            self.cache[id_] = response.geturl()
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
            raise RuntimeError("unexpected content-range: %s" % headers['content-range'])
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
        self.log.info("%s:%d -- %s", *self.client_address, format % args)

    def log_error(self, format, *args):
        self.log.error("%s:%d -- %s", *self.client_address, format % args)

    def log_exception(self, format, *args):
        self.log.exception("%s:%d -- %s", *self.client_address, format % args)

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
        except (socket.timeout, ConnectionError, URLError, GDriveError) as e:
            self.log_error("error communicating with gdrive: %s: %s",
                           type(e).__name__, e)
            self.send_error(502, "Bad Gateway")
            return
        except:
            self.log_exception("non-specific error")
            self.send_error(500, "Internal Server Error")
            return

        with upstream_response:
            self.relay(upstream_response)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', '-p', type=int, default=8989,
                        help="server port (default: %(default)s)")
    parser.add_argument('--address', '-a', default='localhost',
                        help="server address (default: %(default)s)")
    parser.add_argument('--timeout', '-t', type=int, default=5,
                        help="socket timeout (sec) (default: %(default)s)")
    parser.add_argument('--user-agent',
                        help="override user-agent string")
    parser.add_argument('--debug', '-d', type=int, choices=range(3), default=0,
                        help="debug level (2: print headers)")
    parser.add_argument('--cookies', '-c', default='/tmp/gdrive.cookies.txt',
                        help="cookies file (default: %(default)s)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug > 0 else logging.INFO,
                        datefmt='%H:%M:%S',
                        format='%(asctime)s %(levelname)6s: %(name)s: %(message)s')

    cookiejar = MozillaCookieJar(args.cookies)
    if os.path.exists(cookiejar.filename):
        cookiejar.load()
    gdrive = GDriveSession(timeout=args.timeout, debug=(args.debug == 2),
                           user_agent=args.user_agent, cookiejar=cookiejar)
    request_handler = partial(GDriveProxyRequestHandler, gdrive)
    address = (args.address, args.port)
    server = ThreadingHTTPServer(address, request_handler)
    try:
        log.info("bound to address %s! serving requests...", address)
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("interrupted! exiting...")
    finally:
        server.server_close()
        cookiejar.save()


if __name__ == '__main__':
    exit(main())
