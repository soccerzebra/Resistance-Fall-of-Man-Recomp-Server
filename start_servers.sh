#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Start the Resistance: Fall of Man multiplayer server bundle (Linux):
#   medius_server  lobby          TCP 10071-10076
#   svo_http       SVO pages      TCP 10080
#   svo_tls        ticket login   TCP 10443
#   dme_server     game relay     TCP+UDP 10079
# Runs in the foreground; if any server exits, the rest are stopped and the
# script exits non-zero so systemd (deploy/rfom-r1.service) restarts them all.
#
# MP_PUBLIC_HOST defaults to r1.rfom.online; set it to 127.0.0.1 for a
# server on the same PC as the game. Logs: data/*.log.
# ---------------------------------------------------------------------------
set -u
cd "$(dirname "$0")"

export MP_PUBLIC_HOST="${MP_PUBLIC_HOST:-r1.rfom.online}"
export MEDIUS_RESPOND=1
export SWEEP_PACED=reply_0x1F_e.bin
# Python 3.7+ is needed; Rocky 8's python3 is 3.6, so prefer a newer one.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for p in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    command -v "$p" >/dev/null && { PY="$p"; break; }
  done
fi

echo "Starting servers for clients connecting to $MP_PUBLIC_HOST ..."
pids=()
"$PY" -u medius_server.py --sweep & pids+=($!)
"$PY" -u svo_http.py 10080        & pids+=($!)
"$PY" -u svo_tls.py 10443         & pids+=($!)
"$PY" -u dme/dme_server.py        & pids+=($!)

stop_all() { kill "${pids[@]}" 2>/dev/null; wait; }
trap 'stop_all; exit 0' TERM INT

wait -n
echo "A server exited; stopping the rest." >&2
stop_all
exit 1
