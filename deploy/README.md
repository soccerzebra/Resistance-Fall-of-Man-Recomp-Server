# Deploying r1.rfom.online (Rocky Linux)

DNS: an **A** record `r1.rfom.online` -> the VPS's IPv4 address (TTL 300).
No AAAA record: the game is IPv4 only.

Code updates are automatic: `.github/workflows/deploy.yml` copies the repo to
`/opt/rfom-server` and restarts the service on every push to `main`.

## One-time server setup (as root)

    # swap: 512 MB RAM is tight for dnf itself
    fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab

    # Python 3.7+ (Rocky 8's python3 is 3.6; start_servers.sh picks the newest)
    dnf install -y python39 rsync

    # the service user; the deploy key logs in as it
    useradd --system --create-home --home-dir /opt/rfom-server --shell /bin/bash rfom
    mkdir -p /opt/rfom-server/.ssh /opt/rfom-server/data
    echo '<deploy public key>' >> /opt/rfom-server/.ssh/authorized_keys
    chmod 700 /opt/rfom-server/.ssh && chmod 600 /opt/rfom-server/.ssh/authorized_keys
    chown -R rfom:rfom /opt/rfom-server

    # rfom may restart the service and nothing else
    echo 'rfom ALL=(root) NOPASSWD: /usr/bin/systemctl restart rfom-r1, /usr/bin/systemctl is-active rfom-r1' > /etc/sudoers.d/rfom
    chmod 440 /etc/sudoers.d/rfom

    # firewall (and the provider's panel, if it has one)
    firewall-cmd --permanent --add-port=10071-10080/tcp --add-port=10443/tcp --add-port=10079/udp
    firewall-cmd --reload

Copy the existing `data/` folder (TLS key, root, stats) to
`/opt/rfom-server/data/` so clients keep their `svo_root.der`, then run the
deploy workflow once (or copy the code by hand) and:

    cp /opt/rfom-server/deploy/rfom-r1.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now rfom-r1

A change to `deploy/rfom-r1.service` needs those three commands again.

## GitHub secrets

| secret | value |
|---|---|
| `DEPLOY_HOST` | the VPS address |
| `DEPLOY_SSH_KEY` | the deploy private key |
| `DEPLOY_KNOWN_HOSTS` | the VPS's host key line (`ssh-keyscan -t ed25519 <host>`) |

## Status and logs

    systemctl status rfom-r1
    journalctl -u rfom-r1 -f
    tail -f /opt/rfom-server/data/medius.log

`medius_replies.py` and `announcements.txt` are re-read while running. After
the VPS's IP changes, update the A record and restart the service (the
address is resolved at start-up).
