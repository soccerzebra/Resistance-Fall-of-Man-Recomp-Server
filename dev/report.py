#!/usr/bin/env python3
"""Multiplayer: read one SCERT attempt back out of the two logs.

    python tools/mp/report.py [--last N]

Prints, for the most recent connection(s) in logs/mp/medius.log:

  * every candidate the server swept, and the first client reply after it --
    `sweep: client sent ...` names the candidate that made the client talk;
  * the client's own record (type / msg_len / DER length) as it arrived;
  * from logs/mp_scert.log (same run), the kind=4 lines -- type, session state,
    declared msg_len, queue entry -- the kind=6 lines (status + queue head, i.e.
    did the record get consumed) and any kind=7 (reached the no-handler arm).

Nothing here is a guess: each column is one field of one trace call, see the
comment on rfom_mp_scert_note() in project/stubs.cpp for the meanings.

Exit status is 1 when a run has no trace at all, which is the symptom of the
gate being off or the trace file belonging to an older attempt.
"""
import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MEDIUS = os.path.join(ROOT, "logs", "mp", "medius.log")
SCERT = os.path.join(ROOT, "logs", "mp_scert.log")

CONN = re.compile(r"^(\d\d:\d\d:\d\d\.\d+) .*CONNECTED")
SWEEP = re.compile(r"sweep: sending (\S+) \((\d+) B, type (0x[0-9A-F]+)\)")
AFTER = re.compile(r"sweep: client sent (\d+) B after (\S+) \(([^)]*)\)")
SEND = re.compile(r"^(\d\d:\d\d:\d\d\.\d+) .*<-\d+ (\d+) bytes")
DESC = re.compile(r"type (0x[0-9A-F]+)\s+msg_len (\d+) \(0x[0-9A-F]+\)")


def medius(last):
    if not os.path.exists(MEDIUS):
        return
    conns, cur = [], None
    for line in open(MEDIUS, encoding="utf-8", errors="replace"):
        if CONN.search(line):
            cur = {"start": line.split()[0], "sweep": [], "after": None, "client": []}
            conns.append(cur)
            continue
        if cur is None:
            continue
        m = SWEEP.search(line)
        if m:
            cur["sweep"].append((m.group(1), int(m.group(2)), m.group(3)))
            continue
        m = AFTER.search(line)
        if m:
            cur["after"] = (int(m.group(1)), m.group(2), m.group(3))
            continue
        m = SEND.search(line)
        if m:
            cur["client"].append((m.group(1), int(m.group(2))))
            continue
        m = DESC.search(line)
        if m:
            cur["record"] = (m.group(1), int(m.group(2)))

    print(f"=== {MEDIUS} -- last {last} connection(s)")
    for c in conns[-last:]:
        print(f"\n[{c['start']}] client record: {c.get('record', 'not parsed')}")
        # the first <-dump is the client's own certificate record, not a reply
        says = [n for _, n in c['client'][1:]]
        print(f"  client sent after the record: "
              f"{', '.join(f'{n} B' for n in says) or 'nothing'}")
        if c["sweep"]:
            order = " ".join(t[2][2:] for t in c["sweep"])
            print(f"  swept {len(c['sweep'])} candidates in order: {order}")
        if c["after"]:
            print(f"  *** client answered {c['after'][1]} with {c['after'][0]} B "
                  f"({c['after'][2]})")
        elif c["sweep"]:
            print("  client answered none of them")


def scert():
    if not os.path.exists(SCERT):
        print(f"\n=== {SCERT}: missing (gate off, or no connection yet)")
        return False
    lines = open(SCERT, encoding="utf-8", errors="replace").read().splitlines()
    print(f"\n=== {SCERT}: {len(lines)} lines")
    interesting = [l for l in lines if "kind=4" in l or "kind=6" in l or "kind=7" in l]
    for l in interesting[:80]:
        print("  " + l)
    if len(interesting) > 80:
        print(f"  ... {len(interesting) - 80} more kind=4/6/7 lines")
    if not interesting:
        print("  no kind=4/6/7 lines: no record reached the dispatcher")
    caps = [l for l in lines if l.startswith("trace capped")]
    for l in caps:
        print("  " + l)
    return bool(interesting)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--last", type=int, default=2)
    args = ap.parse_args()
    medius(args.last)
    if not scert():
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
