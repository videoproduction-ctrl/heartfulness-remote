#!/usr/bin/env bash
# Heartfulness Remote — server provisioning for Ubuntu 24.04. Run as root.
#
# Safe to run again at any time (idempotent) and fully unattended: it is run
# by cloud-init on first boot (deploy/cloud-init.yaml), by
# scripts/deploy-server.sh over SSH, and by deploy/update.sh.
#
# Usage: provision.sh [domain] [external-ip]
#   domain       default: $HR_DOMAIN, then /etc/heartfulness-remote/domain,
#                then the existing deploy/.env
#   external-ip  default: $HR_EXTERNAL_IP, then the source address of
#                `ip -4 route get 1.1.1.1` (a local routing lookup; no
#                third-party IP service is contacted)
#
# Short progress/status lines: /var/log/heartfulness-remote-setup.log
# Full command output:         /var/log/heartfulness-remote-provision.log
# Secrets (TURN secret) are generated here, on the server, and are never
# printed or logged.
set -Eeuo pipefail
umask 022

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$REPO_DIR/deploy"
ENV_FILE="$DEPLOY_DIR/.env"
TURN_CONF="$DEPLOY_DIR/turnserver.conf"
CONFIG_FILE=/etc/heartfulness-remote/domain
STATE_DIR=/var/lib/heartfulness-remote
STATUS_LOG=/var/log/heartfulness-remote-setup.log
DETAIL_LOG=/var/log/heartfulness-remote-provision.log
CADDY_IP=172.30.77.2
COTURN_GID=65534 # "nogroup" inside the coturn image

export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT=(apt-get -y -q -o DPkg::Lock::Timeout=900 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
COMPOSE=(docker compose --project-name heartfulness-remote -f "$DEPLOY_DIR/docker-compose.yml" --env-file "$ENV_FILE")

CURRENT_STEP="starting"
status() {
	local line
	line="$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
	echo "$line" >>"$STATUS_LOG"
	echo "$line"
}
step() {
	CURRENT_STEP="$*"
	status "STEP $*"
}
# run: send a command's full output to the detail log only.
run() { "$@" >>"$DETAIL_LOG" 2>&1; }
retry() { # retry <attempts> <first-delay-seconds> <command...>
	local max=$1 delay=$2 n=1
	shift 2
	until "$@"; do
		if ((n >= max)); then return 1; fi
		status "  ...retrying in ${delay}s (attempt $((n + 1)) of $max)"
		sleep "$delay"
		n=$((n + 1))
		delay=$((delay * 2))
	done
}
on_error() {
	status "FAILED during: $CURRENT_STEP. Details: $DETAIL_LOG"
	echo "---- last lines of $DETAIL_LOG ----" >&2
	tail -n 25 "$DETAIL_LOG" >&2 || true
}
trap on_error ERR

# read_kv FILE KEY — print the value of KEY=VALUE from FILE (never sourced).
read_kv() {
	[ -r "$1" ] || return 0
	sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" "$1" | tail -n 1 | tr -d '\r"'"'" | sed 's/[[:space:]]*$//'
}

normalize_domain() {
	local d
	d="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
	d="${d#http://}"
	d="${d#https://}"
	d="${d%%/*}"
	d="${d%%:*}"
	d="${d%.}"
	printf '%s' "$d"
}

valid_domain() { [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]; }
valid_ipv4() {
	[[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	local o
	for o in "${BASH_REMATCH[@]:1}"; do ((o <= 255)) || return 1; done
}
private_ipv4() { [[ "$1" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|127\.|169\.254\.) ]]; }

# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$STATUS_LOG")" "$STATE_DIR"
touch "$DETAIL_LOG" && chmod 600 "$DETAIL_LOG"
touch "$STATUS_LOG" && chmod 644 "$STATUS_LOG"

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run this as root (sudo $0)." >&2
	exit 1
fi
for f in docker-compose.yml Caddyfile turnserver.conf.template rebuild.sh systemd/heartfulness-rebuild.service systemd/heartfulness-rebuild.timer; do
	[ -f "$DEPLOY_DIR/$f" ] || {
		status "FAILED: $DEPLOY_DIR/$f is missing (incomplete copy of the project)"
		exit 1
	}
done

# Resolve settings.
DOMAIN="${1:-${HR_DOMAIN:-}}"
[ -n "$DOMAIN" ] || DOMAIN="$(read_kv "$CONFIG_FILE" HR_DOMAIN)"
[ -n "$DOMAIN" ] || DOMAIN="$(read_kv "$ENV_FILE" HR_DOMAIN)"
DOMAIN="$(normalize_domain "$DOMAIN")"
if [ -z "$DOMAIN" ] || [[ "$DOMAIN" == *your-name* ]] || ! valid_domain "$DOMAIN"; then
	status "FAILED: no valid web address configured (got '${DOMAIN:-nothing}'). Put your address on the HR_DOMAIN= line of the cloud-init file (or in $CONFIG_FILE) and run this again."
	exit 1
fi
ACME_EMAIL="${ACME_EMAIL:-$(read_kv "$CONFIG_FILE" ACME_EMAIL)}"
[ -n "$ACME_EMAIL" ] || ACME_EMAIL="$(read_kv "$ENV_FILE" ACME_EMAIL)"
if [ -n "$ACME_EMAIL" ] && ! [[ "$ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
	status "NOTE: ignoring ACME_EMAIL that does not look like an e-mail address"
	ACME_EMAIL=""
fi

status "START provisioning https://$DOMAIN ($(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "copied files"))"

# ---------------------------------------------------------------------------
step "1/9: installing system updates and packages (this can take a few minutes)"
retry 4 15 run "${APT[@]}" update
retry 3 15 run "${APT[@]}" upgrade
retry 3 15 run "${APT[@]}" install docker.io docker-compose-v2 ufw fail2ban python3-systemd \
	unattended-upgrades openssl iproute2 git ca-certificates curl

# ---------------------------------------------------------------------------
step "2/9: enabling automatic security updates"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat >/etc/apt/apt.conf.d/52heartfulness-remote <<'EOF'
// Heartfulness Remote: reboot automatically when a security update (e.g. a
// new kernel) needs it. 21:30 UTC is 03:00 in India; containers restart on
// their own after a reboot.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "21:30";
EOF
run systemctl enable --now unattended-upgrades

# ---------------------------------------------------------------------------
step "3/9: hardening SSH (keys only, no passwords)"
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/10-heartfulness-remote.conf <<'EOF'
# Heartfulness Remote: key-only SSH. (Loaded before cloud-init's 50-*.conf,
# so these values win.)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
EOF
if sshd -t >>"$DETAIL_LOG" 2>&1; then
	systemctl reload ssh >>"$DETAIL_LOG" 2>&1 || systemctl reload sshd >>"$DETAIL_LOG" 2>&1 || true
else
	rm -f /etc/ssh/sshd_config.d/10-heartfulness-remote.conf
	status "NOTE: SSH config check failed; left SSH settings unchanged"
fi
if ! grep -qs '^ssh-\|^ecdsa-\|^sk-' /root/.ssh/authorized_keys; then
	status "NOTE: no SSH key is installed, so SSH login is disabled. That is fine: setup and updates do not need it."
fi

# ---------------------------------------------------------------------------
step "4/9: configuring the firewall"
run ufw default deny incoming
run ufw default allow outgoing
run ufw limit 22/tcp comment 'SSH (rate limited)'
run ufw allow 80/tcp comment 'HTTP (Lets Encrypt + redirect)'
run ufw allow 443/tcp comment 'HTTPS'
run ufw allow 443/udp comment 'HTTPS (HTTP/3)'
run ufw allow 3478/tcp comment 'TURN'
run ufw allow 3478/udp comment 'TURN'
run ufw allow 49160:49200/udp comment 'TURN relay ports'
run ufw --force enable

cat >/etc/fail2ban/jail.d/heartfulness-remote.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
EOF
run systemctl enable fail2ban
run systemctl restart fail2ban

# ---------------------------------------------------------------------------
step "5/9: system settings (7-day log retention, Docker)"
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/heartfulness-remote.conf <<'EOF'
[Journal]
MaxRetentionSec=7day
SystemMaxUse=200M
EOF
run systemctl restart systemd-journald

mkdir -p /etc/docker
DAEMON_JSON='{
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true
}'
if [ "$(cat /etc/docker/daemon.json 2>/dev/null || true)" != "$DAEMON_JSON" ]; then
	if [ -f /etc/docker/daemon.json ]; then cp /etc/docker/daemon.json "/etc/docker/daemon.json.bak.$(date +%s)"; fi
	printf '%s\n' "$DAEMON_JSON" >/etc/docker/daemon.json
	run systemctl enable docker
	run systemctl restart docker
fi
run systemctl enable --now docker

# Small servers (1 GB RAM) need swap to compile the images.
mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
if [ "${mem_kb:-0}" -lt 2000000 ] && [ "$(swapon --noheadings 2>/dev/null | wc -l)" -eq 0 ]; then
	if [ ! -f /swapfile ]; then
		run fallocate -l 2G /swapfile
		chmod 600 /swapfile
		run mkswap /swapfile
	fi
	run swapon /swapfile
	grep -qs '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
	status "  added 2 GB of swap (small server)"
fi

# ---------------------------------------------------------------------------
step "6/9: writing the server configuration (secrets stay on this server)"
DETECTED_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
EXTERNAL_IP="${2:-${HR_EXTERNAL_IP:-}}"
if [ -n "$EXTERNAL_IP" ] && ! valid_ipv4 "$EXTERNAL_IP"; then
	status "NOTE: ignoring invalid external IP '$EXTERNAL_IP'"
	EXTERNAL_IP=""
fi
[ -n "$EXTERNAL_IP" ] || EXTERNAL_IP="$DETECTED_IP"
if ! valid_ipv4 "$EXTERNAL_IP"; then
	status "FAILED: could not determine this server's IPv4 address"
	exit 1
fi
if private_ipv4 "$EXTERNAL_IP"; then
	status "NOTE: this server's address $EXTERNAL_IP is private (behind NAT). The relay may not work until HR_EXTERNAL_IP is set to the public address (scripts/deploy-server.sh does this)."
fi

TURN_SECRET="$(read_kv "$ENV_FILE" HR_TURN_SECRET)"
if ! [[ "$TURN_SECRET" =~ ^[0-9a-f]{64}$ ]]; then
	TURN_SECRET="$(openssl rand -hex 32)"
	status "  generated a new TURN secret"
fi
HOST_PUBKEY="$(read_kv "$ENV_FILE" HR_HOST_PUBKEY)"
[[ "$HOST_PUBKEY" =~ ^[A-Za-z0-9_-]{43}$ ]] || HOST_PUBKEY=""

(
	umask 077
	tmp="$(mktemp "$DEPLOY_DIR/.env.XXXXXX")"
	cat >"$tmp" <<EOF
# Generated by deploy/provision.sh on $(date -u +%Y-%m-%d). Contains secrets:
# never copy this file off the server. Re-running provision.sh keeps the secret.
HR_DOMAIN=$DOMAIN
HR_ORIGIN=https://$DOMAIN
HR_TURN_SECRET=$TURN_SECRET
HR_EXTERNAL_IP=$EXTERNAL_IP
HR_TRUSTED_PROXIES=$CADDY_IP/32
ACME_EMAIL=$ACME_EMAIL
HR_HOST_PUBKEY=$HOST_PUBKEY
EOF
	chmod 600 "$tmp"
	mv -f "$tmp" "$ENV_FILE"
)

# A failed earlier start can leave a directory where the bind-mounted file goes.
if [ -d "$TURN_CONF" ]; then rmdir "$TURN_CONF"; fi
before_turn="$(sha256sum "$TURN_CONF" 2>/dev/null | cut -d' ' -f1 || true)"
(
	umask 077
	tmp="$(mktemp "$DEPLOY_DIR/.turnserver.XXXXXX")"
	sed -e "s|@HR_TURN_SECRET@|$TURN_SECRET|g" \
		-e "s|@HR_DOMAIN@|$DOMAIN|g" \
		-e "s|@HR_EXTERNAL_IP@|$EXTERNAL_IP|g" \
		"$DEPLOY_DIR/turnserver.conf.template" >"$tmp"
	chown "root:$COTURN_GID" "$tmp"
	chmod 640 "$tmp"
	mv -f "$tmp" "$TURN_CONF"
)
after_turn="$(sha256sum "$TURN_CONF" | cut -d' ' -f1)"
caddy_sum="$(sha256sum "$DEPLOY_DIR/Caddyfile" | cut -d' ' -f1)"
# Keep the settings file in sync so later runs (update.sh, weekly jobs) use
# the same address.
mkdir -p /etc/heartfulness-remote
printf 'HR_DOMAIN=%s\nACME_EMAIL=%s\n' "$DOMAIN" "$ACME_EMAIL" >"$CONFIG_FILE"

# ---------------------------------------------------------------------------
step "7/9: installing the weekly security rebuild"
for unit in heartfulness-rebuild.service heartfulness-rebuild.timer; do
	sed "s|@REPO_DIR@|$REPO_DIR|g" "$DEPLOY_DIR/systemd/$unit" >"/etc/systemd/system/$unit"
done
chmod 755 "$DEPLOY_DIR/rebuild.sh" "$DEPLOY_DIR/update.sh" "$DEPLOY_DIR/provision.sh" 2>/dev/null || true
run systemctl daemon-reload
run systemctl enable --now heartfulness-rebuild.timer

# ---------------------------------------------------------------------------
step "8/9: building and starting Heartfulness Remote (first time: about 5 minutes)"
retry 3 30 run "${COMPOSE[@]}" pull --quiet caddy coturn
retry 3 30 run "${COMPOSE[@]}" build --pull server
run "${COMPOSE[@]}" up -d --remove-orphans
# Bind-mounted config files are not watched by compose: restart on change.
if [ "$before_turn" != "$after_turn" ]; then run "${COMPOSE[@]}" restart coturn; fi
if [ "$(cat "$STATE_DIR/caddyfile.sha256" 2>/dev/null || true)" != "$caddy_sum" ]; then
	run "${COMPOSE[@]}" restart caddy
	echo "$caddy_sum" >"$STATE_DIR/caddyfile.sha256"
fi
run docker image prune -f

healthy=""
for _ in $(seq 1 60); do
	cid="$("${COMPOSE[@]}" ps -q server 2>/dev/null || true)"
	if [ -n "$cid" ] && [ "$(docker inspect --format '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)" = "healthy" ]; then
		healthy=yes
		break
	fi
	sleep 3
done
if [ -z "$healthy" ]; then
	run "${COMPOSE[@]}" ps
	run "${COMPOSE[@]}" logs --tail 50 server
	CURRENT_STEP="waiting for the server to become healthy"
	false
fi

# ---------------------------------------------------------------------------
step "9/9: checking the web address"
resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
if [ -z "$resolved" ]; then
	status "NOTE: $DOMAIN does not exist in DNS yet. Point it at $EXTERNAL_IP (an A record); the certificate is issued automatically a few minutes later."
elif [[ " $resolved " != *" $EXTERNAL_IP "* ]]; then
	status "NOTE: $DOMAIN points to ${resolved% } but this server is $EXTERNAL_IP. Update the A record; the certificate follows automatically."
elif curl -fsS --max-time 15 "https://$DOMAIN/healthz" >/dev/null 2>&1; then
	status "  https://$DOMAIN is up with a valid certificate"
else
	status "NOTE: DNS is correct; the HTTPS certificate is still being issued (usually 1-5 minutes)."
fi

touch "$STATE_DIR/provisioned"
status "DONE Heartfulness Remote is running. Your address: https://$DOMAIN"
