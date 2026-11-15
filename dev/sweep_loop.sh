#!/usr/bin/env bash
# Drive the state-0x08 type sweep unattended.
#
# One iteration = bring the game back to the main menu, click
# DOWN DOWN ENTER ENTER so the client dials :10071, let the one-connection
# sweep run, then read the outcome:
#
#   "recv failed after reply_0xNN_y.bin"  -> that candidate is fatal; exclude it
#                                            and go again
#   "client sent N B after reply_0xNN_y"  -> N != 4 and NN past the verified
#                                            prefix: the client answered a
#                                            candidate we did not already know
#                                            about. That is the finding; stop.
#
# Exclusions land in tools/mp/sweep_skip.txt (medius_server.py reads it at
# import), so a re-run never repeats a fatal candidate.
#
# Usage: tools/mp/sweep_loop.sh [iterations] [settle_seconds]
set -u
cd "$(dirname "$0")/../.."

MAX_ITERS=${1:-5}
SETTLE=${2:-34}
LOG=logs/mp/medius.log
SKIP=tools/mp/sweep_skip.txt
PS='powershell.exe -ExecutionPolicy Bypass'
WING='G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling'

kill_server() {
    # every stray server holds :10071, and medius_server.py silently walks to
    # the next free port -- which the game never dials. Kill all of them.
    local pids pid
    pids=$(cmd.exe /c tasklist 2>/dev/null | grep -i python | awk '{print $2}')
    for pid in $pids; do cmd.exe /c "taskkill /PID $pid /F" >/dev/null 2>&1; done
    sleep 2
    while cmd.exe /c tasklist 2>/dev/null | grep -qi python; do sleep 2; done
}

start_server() {
    kill_server
    # medius.log is truncated by each run, so "this run" is the whole file
    ( cmd.exe /c "tools\\mp\\launch_server.bat" >/dev/null 2>&1 & )
    for _ in $(seq 1 20); do
        sleep 1
        grep -q "listening TCP :10071" "$LOG" 2>/dev/null && return 0
        if grep -q "medius v0 starting" "$LOG" 2>/dev/null && ! grep -q ":10071" "$LOG" 2>/dev/null; then
            echo "!! server bound the wrong port (should be 10071)"
            return 1
        fi
    done
    echo "!! server did not come up"
    return 1
}

menu_ok() {
    # the front end returns to a CAMPAIGN-highlighted main menu after a failed
    # attempt; if the click does not reach it the attempt is wasted, so check.
    $PS -File "$WING\\tools\\mp\\shot.ps1" >/dev/null 2>&1
    $PS -Command "\$s=Get-Content -Raw 'logs/mp/screen.png' -ErrorAction SilentlyContinue; if(-not \$s){exit 1}"
    return 0
}

attempt() {
    local out
    out=$($PS -File "$WING\\tools\\mp\\auto_click.ps1" -Count 1 2>&1)
    echo "$out" | grep -qi "sent DOWN" && return 0
    echo "$out" | tail -2
    return 1
}

for i in $(seq 1 "$MAX_ITERS"); do
    echo "=== iteration $i  ($(date +%H:%M:%S))"
    start_server || exit 1
    attempt || { echo "!! click failed"; exit 1; }
    sleep "$SETTLE"

    seg=$(cat "$LOG")
    # the record name has no fixed shape: reply_0x08.bin, reply_0x1B_b.bin,
    # reply_0x0C_any.bin. Matching a mandatory _letter silently dropped the
    # plain names, so an abort on reply_0x08.bin looked like "no abort".
    fatal=$(echo "$seg" | grep -o "recv failed after reply_0x[0-9A-Fa-f][0-9A-Fa-f][_.a-z0-9]*\.bin" | tail -1 | sed 's/.*reply_//')
    sent=$(echo "$seg" | grep -o "client sent [0-9]* B after reply_0x[0-9A-Fa-f]*_[a-z]*" | tail -1)

    echo "   last client send: ${sent:-none}"
    if [ -n "$fatal" ]; then
        echo "   fatal: $fatal -> excluded"
        echo "reply_$fatal" >> "$SKIP"   # full record filename: the server matches basenames
        continue
    fi
    # no abort at all: either the sweep completed or the client gave up early
    # the real success test: session state moved off 0x08 (dispatch trace)
    # kind=4 fields: a=type b=[sess+8] c=msg_len d=handler entry. The state is
    # b -- reading c made every record look like a state change (0x26 is the
    # 38-byte payload length, not a state).
    st=$(grep "kind=4" logs/mp_scert.log | tail -1 | sed -n 's/.* b=0x\([0-9A-F]*\).*/\1/p')
    if [ -n "$st" ] && [ "$st" != "00000008" ]; then
        echo "   >>> SESSION STATE MOVED: [sess+8]=0x$st (was 0x08)"
        exit 0
    fi
    if echo "$seg" | grep -q "sweep done"; then
        echo "   sweep completed with no abort -- check the sends above by hand"
    fi
    case "$sent" in
        # known client messages: 0x1A_s -> 0x0B, 0x25_g -> 00 48, 0x22 -> 0x23
        # (login), 0x07 -> 0x21, and 4 B = 20 01 00 01 give-up.
        *" 4 B "*) : ;;
        *"0x1A_s"*|*"0x25_g"*|*"reply_0x22.bin"*|*"reply_0x07.bin"*) : ;;
        *) echo "   >>> CLIENT ANSWERED A NEW CANDIDATE: $sent"; exit 0 ;;
    esac
done
echo "=== stopped after $MAX_ITERS iteration(s); exclusions:"
cat "$SKIP"
