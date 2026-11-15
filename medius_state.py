"""Shared lobby state for the local Medius server (v184).

medius_replies.py is reloaded whenever it changes, which would wipe anything
kept in it. State that must outlive a reload -- the games that exist, the
next world ID, which connection is which player -- lives here instead; this
module is imported once and never reloaded.
"""
import threading

LOCK = threading.RLock()
GAMES = {}            # world_id -> dict(name, stats, fields..., host, players)
NEXT_WORLD = [100]
NEXT_FILTER = [1]
SESSIONS = {}         # id(conn) -> dict(account_id, name, world_id, conn)


def new_world_id():
    with LOCK:
        NEXT_WORLD[0] += 1
        return NEXT_WORLD[0]
