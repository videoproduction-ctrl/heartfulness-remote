# Server operator notes

Short reference for whoever looks after the Heartfulness Remote server (a
small Ubuntu 24.04 VPS). The owner never needs this: the server installs,
renews its certificate, patches and rebuilds itself.

## What runs where

```
Internet ──► 80/tcp, 443/tcp, 443/udp ──► caddy  (HTTPS, Let's Encrypt)
                                            │  internal Docker network 172.30.77.0/24
                                            ▼  (caddy is fixed at 172.30.77.2)
                                          server (heartfulness-server :8080, not published)
Internet ──► 3478/tcp+udp, 49160-49200/udp ──► coturn (TURN/STUN relay, host network)
```

| Path on the server | What it is |
|---|---|
| `/opt/heartfulness-remote/` | the code (a git checkout, or files copied by `scripts/deploy-server.sh`) |
| `/opt/heartfulness-remote/deploy/.env` | settings + TURN secret, generated on the server, mode 0600, never leaves it |
| `/opt/heartfulness-remote/deploy/turnserver.conf` | coturn config rendered from `turnserver.conf.template`, mode 0640 root:nogroup |
| `/etc/heartfulness-remote/domain` | the web address (written by cloud-init) |
| Docker volume `heartfulness-remote_server_data` | server state: owner, passkeys, devices, sessions, 7-day event log |
| Docker volumes `heartfulness-remote_caddy_*` | certificates |

Containers: `caddy` (root, all capabilities dropped except binding 80/443),
`server` (uid 65532, read-only root filesystem, no capabilities, reachable
only by caddy), `coturn` (user nobody, read-only, `use-auth-secret`, refuses
to relay to private/reserved addresses). All have `no-new-privileges`.
Image versions are pinned in `docker-compose.yml` (`docker.io/library/caddy:2.11.7`,
`docker.io/coturn/coturn:4.18.0`) and in `server/Dockerfile`; change them
there, then run `scripts/test-deploy.sh` (also run by CI), which checks the
compose file, starts that coturn with the real config and tests TURN
authentication and the relay deny list.

Firewall (ufw): incoming denied except 22/tcp (rate limited), 80/tcp,
443/tcp+udp, 3478/tcp+udp, 49160-49200/udp. Docker-published ports bypass
ufw, which is why only caddy's 80/443 are published. SSH accepts keys only
(no passwords; root by key only); fail2ban bans repeated SSH failures.

## Install

* **Main path (no SSH):** paste `cloud-init.yaml` into the provider's "User
  data" box when creating the server, after replacing `YOUR-NAME.duckdns.org`
  on the `HR_DOMAIN=` line. A boot-time service clones the public repository
  and runs `provision.sh`; it retries at every boot until it succeeds.
* **With SSH:** from a Mac or Linux checkout,
  `./scripts/deploy-server.sh <server-ip> <domain> [ssh-key]`.

Point the domain's A record at the server's IPv4 address before or after;
Caddy keeps retrying the certificate on its own.

## Everyday commands (as root)

```sh
cd /opt/heartfulness-remote/deploy
docker compose ps                                   # all three should be "Up", server "healthy"
docker compose logs --tail 50 server                # or caddy / coturn
docker compose exec server /heartfulness-server status   # claimed? Mac fingerprint, device counts (no secrets)
docker compose restart server
tail /var/log/heartfulness-remote-setup.log         # one line per setup/update/rebuild step
```

## Updating

* **Automatic, weekly:** `heartfulness-rebuild.timer` (Sundays 20:30 UTC)
  rebuilds the images from the code that is already there (no new code is
  downloaded) to pick up patched base images, then restarts what changed.
  `systemctl list-timers heartfulness-rebuild.timer`, `journalctl -u heartfulness-rebuild`.
* **Ubuntu security updates:** unattended-upgrades, with an automatic reboot
  at 21:30 UTC when one needs it. Containers come back on their own.
* **New version of the project:** `/opt/heartfulness-remote/deploy/update.sh`
  (latest `main`) or `update.sh v1.2.0` (a tag) on git installs; on
  installs made by `deploy-server.sh`, run that script again. Both re-run
  `provision.sh`, which keeps `.env` (and so the TURN secret) as it is.

`provision.sh`, `update.sh` and the weekly rebuild share a lock
(`/run/heartfulness-remote.lock`) so they never overlap. Re-running
`provision.sh` is always safe. If a rebuild or update fails (for example
the network is down), the containers that were running keep running.

## Reset (lost passkeys, or the wrong Mac claimed the server)

The reset refuses to run while the server is running:

```sh
cd /opt/heartfulness-remote/deploy
docker compose stop server
docker compose run --rm --no-deps server reset --confirm
docker compose start server
```

This forgets the owner, passkeys, the Mac binding, all devices and sessions.
The Mac then shows a new setup QR code. Certificates and the TURN secret stay.

To rotate the TURN secret: delete the `HR_TURN_SECRET=` line from `.env` and
run `provision.sh` again. A new secret is generated, coturn and the server
restart, and the Mac and clients get new TURN credentials when they
reconnect a few seconds later.

## Logs and the 7-day limit

* The server keeps its own event log (logins, device and session events,
  with IP addresses) for 7 days; an hourly job deletes older entries, expired
  sessions and stale pending devices. It stores no screen, audio or file data.
* Every other log (system, SSH, firewall, and the containers through
  Docker's journald driver) is kept only in the systemd journal, for at most
  7 days (`/etc/systemd/journald.conf.d/heartfulness-remote.conf`:
  `MaxRetentionSec=7day`, `MaxFileSec=1day`, 200 MB cap). rsyslog is told to
  discard everything (`/etc/rsyslog.d/00-heartfulness-remote.conf`), so
  nothing lands in `/var/log/syslog`, `auth.log` or `ufw.log`.
* Caddy writes no access log. coturn logs relay sessions (with client IPs),
  which therefore also disappear after 7 days.
* Setup logs with no client data: `/var/log/heartfulness-remote-setup.log`
  (short) and `/var/log/heartfulness-remote-provision.log` (full output of
  the last run; the run before is in `.1`).
* Not covered: Ubuntu's login records `/var/log/wtmp` and `btmp` (SSH logins,
  rotated monthly) and cloud-init's own logs of the first boot.

## When the address shows "offline" or doesn't load

1. `systemctl status heartfulness-remote-setup` and
   `tail -20 /var/log/heartfulness-remote-setup.log`: did setup finish?
2. `docker compose ps`: are all three containers up?
3. `docker compose logs caddy | grep -i -E 'acme|certificate|error'`: is the
   certificate issued? It needs the domain's A record to point at this
   server and ports 80/443 open at the provider's firewall too.
4. The Mac shows "Offline" when it cannot reach `wss://<domain>/ws/host`;
   `docker compose logs server | tail` shows whether it connected.
