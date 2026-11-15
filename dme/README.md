# DME game server

The game-server half of the local multiplayer stack. With it, two copies of
the game can create, find, join and **start** a custom game (tested v185: two
copies on one PC, Nottingham Deathmatch, both players in the level and
exchanging state through the relay).

## Who hosted what (original service)

| piece | ran on | ours |
|---|---|---|
| MAS/MLS lobby (login, lists, create/join requests) | Sony/SCERT servers | `medius_server.py` + `medius_replies.py` |
| SVO web pages, HTTPS ticket login | Sony servers | `svo_http.py`, `svo_tls.py` |
| **DME game server**: connections, client indices, message relay | Sony servers | **`dme_server.py`** |
| the match itself (game state, rules, the "session master") | **a player's PS3** | the game, unchanged (the creator, DME index 0) |

## Protocol (read from the client's handlers)

Standard SCE-RT record numbering. Handshake: client `0x24` HELLO -> server
`0x22` CONNECT_REQUIRE + `0x25` HELLO(398); client `0x23` + `0x00`
CONNECT_TCP (u32 world, u16 app) -> server `0x07` CONNECT_ACCEPT (u16 index,
u32 scert, u16 count, ip[16]); client `0x21` -> server `0x1A` CONNECT_COMPLETE
(u16 count) and `0x08` CONNECT_NOTIFY both ways (u16 idx, u32 scert, ip[16],
key[64]). Leaving -> `0x09` (22 B). App traffic: client `0x02` broadcast /
`0x03` single (u16 target) / `0x04` list (u8 n, mask[n]) are delivered as
`[u16 source index][data]`. `0x2D` timebase query -> `0x2E` (echo, server ms).
`0x1F` pings keep the client's 3 s timer alive.

## Lobby side (medius_replies.py)

- CreateGame `4/0x2F` -> `4/0x4F` {Status, WorldID} (the reply type matters:
  replies are paired by MessageID, and each type's handler reads the status from
  its own offset). The client then JoinGames that world and becomes index 0.
- WorldReport `4/0x30` (host, every ~15 s): stored -- GameStats carry the map /
  mode; games without a report for 60 s drop out of the list.
- JoinGame `1/0xF3` -> NetConnectionInfo pointing at this server.

## Run

See the top-level README (`start_servers.bat`). Alone:

    python dme/dme_server.py [port]      (default 10079, TCP and UDP)

TCP_NODELAY is set on lobby and DME connections.

## Open

- The host's view in the level was a flat yellow screen (HUD drawn, world not)
  while the joiner rendered normally -- render-side, not network.
- The auxiliary UDP channel is never requested so far (TCP carries everything).
- Accounts are not per player yet (every login is account 1001).
