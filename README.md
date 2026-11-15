# Resistance: Fall of Man — community multiplayer server

A stand-in for the retired online services that *Resistance: Fall of Man*
(PS3) used, for the PC recompilation
([Resistance-Fall-of-Man-Recomp](https://github.com/soccerzebra/Resistance-Fall-of-Man-Recomp)).
With it, players can sign in, see announcements, and create, find, join and
play custom games.

Pure Python 3 (standard library only). No game files are needed to run it.

## What runs

| piece | file | port |
|---|---|---|
| Medius lobby (login, policy, announcements, game lists, create/join) | `medius_server.py` + `medius_replies.py` | TCP 10071–10076 |
| SVO pages (URL list, create-game hooks) | `svo_http.py` | TCP 10080 |
| SVO ticket login (SSL 3.0, RC4-MD5) | `svo_tls.py` | TCP 10443 |
| DME game server: connections, client indices, message relay | `dme/dme_server.py` | TCP + UDP 10079 |

The match itself (rules, game state) runs on the hosting player's game, as it
did on PS3; the server only relays.

The public server is **r1.rfom.online** (Rocky Linux VPS, systemd); setup
steps are in `deploy/README.md`.

## Run

    start_servers.bat        :: Windows: all four, in the background (local, 127.0.0.1)
    stop_servers.bat
    ./start_servers.sh       # Linux: all four, foreground (r1.rfom.online by default)

Logs, saved player stats and the generated TLS keys go to `data\`
(`MP_DATA_DIR` overrides). `replies\` holds the canned Medius/DME handshake
records.

### Remote hosting

    set MP_PUBLIC_HOST=r1.rfom.online
    start_servers.bat

`MP_PUBLIC_HOST` (an IP or a domain name) is the address clients are told to
connect to: lobby, SVO, DME and the TLS certificate name. A domain is resolved
at start-up and clients are handed its IP, so restart the servers after the
IP changes. Forward TCP 10071–10080, 10443 and UDP 10079.

### What each client needs

1. `net_hosts.txt` (in the game folder) mapping the Sony hostnames to the
   server's address. The launcher's Multiplayer page writes one that maps
   them to `r1.rfom.online`.
2. This server's `data\svo_root.der` (written the first time `svo_tls.py`
   starts). The client patches it over the game's built-in TLS root so the
   ticket login trusts this server: put it at `logs\mp\svo_root.der` in the
   game folder, or set `MP_SVO_ROOT` to its path.

`data\svo_tls_key.json` holds the server's private keys. Keep it private, and
keep it (the clients' `svo_root.der` must match it); deleting it makes a new
root that every client then needs again.

## Configuration

- `announcements.txt` — the lobby announcement (re-read on every login). Only
  the first block is sent for now: a second announcement record hangs the
  client (`MEDIUS_ANNOUNCE_MAX` raises the limit for testing).
- `medius_replies.py` — every lobby request and its reply builder (`RULES`).
  It is reloaded automatically when it changes; no restart needed.
- Environment: `MP_PUBLIC_HOST`, `MP_DATA_DIR`, `SVO_TLS_CN`,
  `DME_PING_GAP`, `DME_FIRST_INDEX`, `MEDIUS_TEST_GAME=1` (adds a fixed test
  game to the list).

## Protocol notes

`dme/README.md` (DME handshake and relay) and the multiplayer plan in the
client repo (`docs/MULTIPLAYER-PLAN.md`), which records how each message
layout was read from the game's own (de)serializers.

`replies/reply_0x03/04/05/07/22.bin` carry the game's public SCERT
certificate (from the game binary, no private key); the client checks the
server presents it.

`dev/` holds the research tools used to work the protocol out (port taps,
TLS probe, record builders, sweep drivers). They still assume the client
repo's layout (`tools/mp/`, `logs/mp/`).
