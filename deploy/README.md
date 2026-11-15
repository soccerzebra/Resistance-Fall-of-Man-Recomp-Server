# Deploying r1.rfom.online (Rocky Linux)

DNS: an **A** record `r1.rfom.online` -> the VPS's IPv4 address (TTL 300).
No AAAA record: the game is IPv4 only.

Run as root on the VPS:

    # swap: 512 MB RAM is tight for dnf itself
    fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab

    dnf install -y python3 git

    # code, run as its own user
    useradd --system --home /opt/rfom-server --shell /sbin/nologin rfom
    git clone <server repo URL> /opt/rfom-server
    chmod +x /opt/rfom-server/start_servers.sh

    # firewall (also open the same ports in the provider's panel, if it has one)
    firewall-cmd --permanent --add-port=10071-10080/tcp --add-port=10443/tcp --add-port=10079/udp
    firewall-cmd --reload

Copy the existing `data/` folder up (from the PC that ran the server so far),
so the TLS key stays the same and clients keep their `svo_root.der`:

    scp -r data root@r1.rfom.online:/opt/rfom-server/

Then:

    chown -R rfom:rfom /opt/rfom-server
    cp /opt/rfom-server/deploy/rfom-r1.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now rfom-r1

Status and logs:

    systemctl status rfom-r1
    journalctl -u rfom-r1 -f
    tail -f /opt/rfom-server/data/medius.log

Update:

    cd /opt/rfom-server && sudo -u rfom git pull && systemctl restart rfom-r1

`medius_replies.py` and `announcements.txt` are re-read while running; other
changes need the restart. After the VPS's IP changes, update the A record and
restart the service (the address is resolved at start-up).
