# Research tools

Kept for reference: these were used to work the Medius / DME / SVO protocol
out against the running game, before the rule-based server existed. They have
not been moved to this repo's layout -- they expect to sit in the client repo
at `tools/mp/` and read/write `logs/mp/` there (some contain absolute paths
from the original machine).

- `tap.py` — port tap: log what the client sends on a port.
- `tls_probe.py` — decode the client's ClientHello.
- `report.py` — read one connection attempt back out of the logs.
- `make_reply.py` — build certificate / bare records (`replies/` came from it).
- `make_*_reply.py` — one-off record builders.
- `sweep_loop.sh`, `single_loop.sh`, `_paced.bat`, `_start_paced.ps1` —
  unattended record-type sweeps.
- `launch_server.bat`, `run_server.bat` — old launchers.
