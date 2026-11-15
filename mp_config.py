"""Server-wide settings for the multiplayer server bundle.

MP_PUBLIC_HOST is the address CLIENTS use to reach this server bundle. It is
handed out in the lobby's universe reply (lobby + SVO URL), the JoinGame reply
(DME server), the SVO URL list, and it is the TLS certificate name. Default
127.0.0.1 = everything on one PC. For remote play set it to the server's
public IP or domain name before starting every server, and point each
client's net_hosts.txt at the same address. A domain is resolved once at
start-up and clients are handed the IP (the NetAddress fields are char[16]
and the game may not resolve names there), so after the IP changes, update
DNS and restart the servers.

Paths:
  REPLY_DIR  replies/  canned handshake records (committed)
  DATA_DIR   data/     logs, generated TLS keys, saved stats (not committed;
                       MP_DATA_DIR overrides)
"""
import os
import socket

HERE = os.path.dirname(os.path.abspath(__file__))
REPLY_DIR = os.path.join(HERE, 'replies')
DATA_DIR = os.environ.get('MP_DATA_DIR', os.path.join(HERE, 'data'))
os.makedirs(DATA_DIR, exist_ok=True)

PUBLIC_NAME = os.environ.get('MP_PUBLIC_HOST', '127.0.0.1').strip()
try:
    PUBLIC_HOST = socket.gethostbyname(PUBLIC_NAME)   # an IP passes through unchanged
except OSError as e:
    raise SystemExit(f'MP_PUBLIC_HOST {PUBLIC_NAME!r} did not resolve: {e}')
PUBLIC_HOST_B = PUBLIC_HOST.encode()
