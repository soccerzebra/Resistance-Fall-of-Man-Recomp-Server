#!/usr/bin/env python3
"""Local stand-in for the SVO web server R:FoM talks to after Medius login.

The universe reply's SvoURL (make_universe_reply.py) points here. SVO's
browser fetches it and expects an SVML page; a <URL_List> element in it is
handled by URLListTagModule (func_0068D66C), which registers every child
element as name -> URL (func_00685230) and then fires the listener's
"online init complete" (ConnectionStats::handleOnlineInitComplete, cs+0x8 = 2).
That is what releases the online state machine from its state 2 wait (v184).

Every request is logged in full to data/svo_http.log. A file
data/svo/<path with / -> _>.svml overrides the built-in answer for that
path, so a new page needs no restart.

    python svo_http.py [port]        (default 10080)
"""
import http.server, os, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 10080
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mp_config import PUBLIC_HOST, DATA_DIR   # noqa: E402  (MP_PUBLIC_HOST, default 127.0.0.1)
LOG = os.path.join(DATA_DIR, 'svo_http.log')
OVR = os.path.join(DATA_DIR, 'svo')
BASE = f'http://{PUBLIC_HOST}:{PORT}'

# Every *URI key the game looks up (strings in EBOOT.elf).
URI_KEYS = ['TicketLoginURI', 'loginEncryptedURI', 'createGameURI', 'createGamePlayerURI',
            'finishGameURI', 'gamePostBinaryStatsURI', 'playerStatsURI',
            'downloadVerificationURI', 'SetUniversePasswordURI', 'SetIgnoreListURI']


# SVBrowser's ticket login (func_00683DC0) refuses a TicketLoginURI that does
# not start with "https:" (error -101), so that one key goes to a TLS port.
TLS_PORT = int(os.environ.get('SVO_TLS_PORT', '10443'))
HTTPS_KEYS = {'TicketLoginURI'}


def url_list_page():
    # A leading dummy element: the handler starts from the first child's
    # *sibling* (func_0067DD74), so whatever comes first may be skipped.
    items = '\n'.join(
        f'<{k}>https://{PUBLIC_HOST}:{TLS_PORT}/{k}</{k}>' if k in HTTPS_KEYS else f'<{k}>{BASE}/{k}</{k}>'
        for k in URI_KEYS)
    return f'<SVML>\n<URL_List>\n<Dummy>x</Dummy>\n{items}\n</URL_List>\n</SVML>\n'


def default_page(path):
    if path in ('/', ''):
        return url_list_page()
    return '<SVML>\n</SVML>\n'


def log(*parts):
    line = time.strftime('%H:%M:%S') + ' ' + ' '.join(str(p) for p in parts)
    print(line, flush=True)
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write(line + '\n')


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def _serve(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n) if n else b''
        log(f'{self.client_address[0]}:{self.client_address[1]}', self.command, self.path)
        for k, v in self.headers.items():
            log('   ', f'{k}: {v}')
        if body:
            log('    body', repr(body[:2000]))
        key = self.path.split('?')[0].strip('/').replace('/', '_') or 'index'
        ovr = os.path.join(OVR, key + '.svml')
        page = open(ovr, encoding='utf-8').read() if os.path.exists(ovr) else default_page(self.path.split('?')[0])
        data = page.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/svml')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        log('   ->', 200, f'{len(data)} bytes', '(override)' if os.path.exists(ovr) else '(built-in)')

    do_GET = _serve
    do_POST = _serve

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    os.makedirs(OVR, exist_ok=True)
    log(f'svo_http listening on :{PORT}')
    # all interfaces: remote clients fetch these pages too (v185)
    http.server.ThreadingHTTPServer(('0.0.0.0', PORT), H).serve_forever()
