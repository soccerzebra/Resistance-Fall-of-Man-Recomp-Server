#!/usr/bin/env bash
# One candidate per connection, driven unattended.
#
# Why one: past our 0x1A_s the client dispatched only the FIRST record we sent
# (0x1B, trace kind=4 b=0x08) and ignored everything after it -- it is waiting
# for one specific reply and reads our later bytes as that record's remainder.
# A stream sweep therefore proves nothing about candidates 2..N, which is why
# the earlier sweeps kept "tolerating" types they never actually delivered.
#
# Each iteration: verified prefix (03 04 05 07 22 25_g 26_b 2A_a 28_s 1A_s) plus
# candidate index N, one click, ~10 s of observation.
#
# Usage: tools/mp/single_loop.sh <first_index> <count> [settle_seconds]
set -u
cd "$(dirname "$0")/../.."

FIRST=${1:-0}
COUNT=${2:-8}
SETTLE=${3:-10}
LOG=logs/mp/medius.log
TRACE=logs/mp_scert.log
PS='powershell.exe -ExecutionPolicy Bypass'
WING='G:\Resistance-Fall-of-Man-Recomp-dlss-upscaling'

kill_server() {
    local pids
    pids=$(cmd.exe /c tasklist 2>/dev/null | grep -i python | awk '{print $2}')
    for p in $pids; do cmd.exe /c "taskkill /PID $p /F" >/dev/null 2>&1; done
    while cmd.exe /c tasklist 2>/dev/null | grep -qi python; do sleep 1; done
}

for n in $(seq "$FIRST" $((FIRST + COUNT - 1))); do
    echo "=== candidate index $n  ($(date +%H:%M:%S))"
    kill_server
    # env must reach python: launch_server.bat starts the server as a child
    ONLY=${SWEEP_ONLY:-}
    DUPLEX=${SWEEP_DUPLEX:-}
    AFTER=${SWEEP_AFTER:-}
    ( cmd.exe /c "set SWEEP_GAP=${SWEEP_GAP:-0.15}&& set SWEEP_ONLY=$ONLY&& set SWEEP_ONE=$n&& set SWEEP_DUPLEX=$DUPLEX&& set SWEEP_AFTER=$AFTER&& tools\\mp\\launch_server.bat" >/dev/null 2>&1 & )
    for _ in $(seq 1 15); do
        sleep 1; grep -q "listening TCP :10071" "$LOG" 2>/dev/null && break
    done
    cand=$(grep -o "single-candidate mode: index [0-9]* of [0-9]* post-prefix records = reply_[A-Za-z0-9_.]*" "$LOG" | tail -1 | sed 's/.*= //')
    ctype=$(echo "$cand" | sed -n 's/reply_0x\([0-9A-Fa-f][0-9A-Fa-f]\).*/\1/p' | tr 'A-F' 'a-f')
    echo "   candidate: ${cand:-?}"

    out=$($PS -File "$WING\\tools\\mp\\auto_click.ps1" -Count 1 2>&1)
    echo "$out" | grep -qi "sent DOWN" || { echo "!! click failed: $(echo "$out"|tail -1)"; exit 1; }
    sleep "$SETTLE"

    seg=$(cat "$LOG")
    # state after the candidate: kind=4 a=<type> b=<state> c=<len>
    last=$(grep "kind=4" "$TRACE" | tail -1)
    if [ -n "$last" ]; then
        t=$(echo "$last" | sed -n 's/.*a=0x\([0-9A-F]*\).*/\1/p')
        st=$(echo "$last" | sed -n 's/.* b=0x\([0-9A-F]*\).*/\1/p')
        echo "   candidate: $cand   last dispatch: type 0x$t  state 0x$st"
        # only the candidate's own dispatch counts: the prefix dispatches have
        # their own (legitimate) states 0x04, 0x07, 0x0C, and reading the last
        # line blindly flagged those as success.
        tt=$(echo "$t" | sed 's/^0*//' | tr 'A-F' 'a-f')
        ct=$(echo "$ctype" | sed 's/^0*//')
        if [ -n "$st" ] && [ "$tt" = "$ct" ] && [ "$st" != "00000008" ]; then
            echo "   >>> STATE=0x$st after type 0x$t -- candidate $cand"
            exit 0
        fi
    fi
    # prefix records provoke their own known sends: 0x07->0x21, 0x22->0x23,
    # 0x25_g->00 48, 0x1A_s->0x0B. Only a send after our ONE candidate counts.
    dup=$(echo "$seg" | grep -o "duplex.*" | tail -2)
    [ -n "$dup" ] && echo "   $dup"
    newsend=$(echo "$seg" | grep -o "client sent [0-9]* B after [^ ]* ([0-9a-f ]*)" \
        | grep -Ev "0x1A_s|0x25_g|reply_0x22\.bin|reply_0x07\.bin|0x03\.bin|0x04\.bin|0x05\.bin" | tail -1)
    if [ -n "$newsend" ] && ! echo "$newsend" | grep -q "0x30_b"; then
        case "$newsend" in
            *"20 01 00 01"*) : ;;
            *) echo "   >>> CLIENT SENT: $newsend  (candidate $cand)"; exit 0 ;;
        esac
    fi
done
echo "=== done: no candidate in this range provoked anything"
