#!/usr/bin/env bash
# Heartfulness Remote — install or update the server over SSH.
#
# This is the secondary path. The main path needs no SSH at all: paste
# deploy/cloud-init.yaml into the "User data" box when creating the server.
#
# Usage:
#   ./scripts/deploy-server.sh <server-ip> <domain> [ssh-key]
#
#   server-ip  the server's public IPv4 address, e.g. 203.0.113.10
#   domain     its web address, e.g. heartfulness-remote.duckdns.org
#   ssh-key    optional: the private key file to log in with
#              (default: your usual SSH keys / ssh-agent)
#
# Optional settings (environment variables):
#   HR_SSH_USER=ubuntu        log in as this user and use sudo (default: root)
#   HR_SSH_PORT=22            SSH port (default: 22)
#   ACME_EMAIL=you@example    e-mail for Let's Encrypt expiry notices
#   HR_WAIT_MINUTES=15        how long to wait for HTTPS at the end
#
# What it does:
#   1. checks it can log in to the server,
#   2. packs the parts of this project the server needs (.dockerignore,
#      proto/, server/, web/, deploy/; files tracked by git only, so nothing
#      git-ignored such as .env files or keys ever leaves this computer),
#   3. copies them to /opt/heartfulness-remote, keeping the server's own
#      secrets (deploy/.env, deploy/turnserver.conf), which never leave it,
#   4. runs deploy/provision.sh there (firewall, updates, HTTPS, services),
#   5. waits until https://<domain>/healthz answers with a valid certificate.
# Run it again at any time to update the server to this copy of the code.
#
# Works on macOS (its built-in bash 3.2) and Linux. Prints no secrets.
set -euo pipefail

say() { printf '%s\n' "$*"; }
fail() {
	printf '\nProblem: %s\n' "$*" >&2
	exit 1
}
usage() {
	say "Usage: $0 <server-ip> <domain> [ssh-key]"
	say "  e.g. $0 203.0.113.10 heartfulness-remote.duckdns.org ~/.ssh/id_ed25519"
	say "Optional: HR_SSH_USER=ubuntu, HR_SSH_PORT=22, ACME_EMAIL=you@example.org"
	exit 2
}

if [ $# -lt 2 ] || [ $# -gt 3 ]; then usage; fi
SERVER_IP=$1
DOMAIN=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]' | sed -e 's#^https\{0,1\}://##' -e 's#[/:].*$##' -e 's#\.$##')
KEY=${3:-}
SSH_USER=${HR_SSH_USER:-root}
SSH_PORT=${HR_SSH_PORT:-22}
ACME_EMAIL=${ACME_EMAIL:-}
WAIT_MINUTES=${HR_WAIT_MINUTES:-15}

# ---- check the inputs (they are also passed to the server, so be strict) ----
ip_re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
if ! [[ $SERVER_IP =~ $ip_re ]]; then
	fail "'$SERVER_IP' is not an IPv4 address. Use the server's public IPv4 address, like 203.0.113.10 (shown in your provider's control panel)."
fi
for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
	[ "$((10#$octet))" -le 255 ] || fail "'$SERVER_IP' is not a valid IPv4 address."
done
domain_re='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$'
if ! [[ $DOMAIN =~ $domain_re ]]; then
	fail "'$2' is not a web address. Use the full name, like heartfulness-remote.duckdns.org."
fi
if [ -n "$KEY" ] && [ ! -r "$KEY" ]; then
	fail "cannot read the SSH key file '$KEY'."
fi
user_re='^[a-z_][a-z0-9_-]{0,31}$'
[[ $SSH_USER =~ $user_re ]] || fail "HR_SSH_USER '$SSH_USER' is not a valid user name."
port_re='^[0-9]{1,5}$'
if ! [[ $SSH_PORT =~ $port_re ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
	fail "HR_SSH_PORT '$SSH_PORT' is not a valid port."
fi
email_re='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
if [ -n "$ACME_EMAIL" ] && ! [[ $ACME_EMAIL =~ $email_re ]]; then
	fail "ACME_EMAIL '$ACME_EMAIL' does not look like an e-mail address."
fi
[[ $WAIT_MINUTES =~ $port_re ]] || fail "HR_WAIT_MINUTES must be a number of minutes."
for tool in ssh tar curl; do
	command -v "$tool" >/dev/null 2>&1 || fail "the '$tool' command is missing on this computer."
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -f "$ROOT/deploy/provision.sh" ] || [ ! -f "$ROOT/server/Dockerfile" ]; then
	fail "run this from a complete copy of the Heartfulness Remote project."
fi

WORK="$(mktemp -d /tmp/hr-deploy.XXXXXX)"
cleanup() {
	ssh -o ControlPath="$WORK/ssh" -O exit "$SSH_USER@$SERVER_IP" >/dev/null 2>&1 || true
	rm -rf -- "$WORK"
}
trap cleanup EXIT

# One SSH connection is reused for every step (one key/passphrase prompt).
SSH=(ssh -p "$SSH_PORT"
	-o ControlMaster=auto -o ControlPath="$WORK/ssh" -o ControlPersist=120
	-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20
	-o ServerAliveInterval=30 -o ServerAliveCountMax=10)
if [ -n "$KEY" ]; then SSH+=(-i "$KEY" -o IdentitiesOnly=yes); fi
SSH+=("$SSH_USER@$SERVER_IP")
SUDO=""
if [ "$SSH_USER" != "root" ]; then SUDO="sudo -n "; fi

# ---- 1. log in ----
say "1/5 Logging in to $SSH_USER@$SERVER_IP ..."
if ! "${SSH[@]}" "${SUDO}true"; then
	fail "could not log in to $SSH_USER@$SERVER_IP with SSH.
  - Check the IP address in your provider's control panel.
  - The server must have your SSH public key (added when the server was created),
    or pass the private key file as the third argument.
  - If you log in as another user than root, set HR_SSH_USER (it needs sudo
    without a password, as on standard cloud images)."
fi
# shellcheck disable=SC2016 # $ID and $VERSION_ID expand on the server
os="$("${SSH[@]}" '. /etc/os-release 2>/dev/null && printf "%s %s" "$ID" "$VERSION_ID"' || true)"
if [ "$os" != "ubuntu 24.04" ]; then
	say "    Note: this server runs '${os:-an unknown system}'; Heartfulness Remote is made for Ubuntu 24.04. Trying anyway."
fi

# ---- 2. pack ----
say "2/5 Packing the server software ..."
LIST="$WORK/files"
: >"$LIST"
REV="copied"
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	REV="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
	if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no -- .dockerignore proto server web deploy)" ]; then
		REV="$REV-modified"
	fi
	git -C "$ROOT" ls-files -z -- .dockerignore proto server web deploy |
		while IFS= read -r -d '' f; do
			case "$f" in
			*/.env | */.env.* | *.key | *.pem | *.p12 | *.p8 | */secrets/* | deploy/turnserver.conf)
				[ "$f" = deploy/.env.example ] || continue
				;;
			esac
			if [ -e "$ROOT/$f" ] || [ -L "$ROOT/$f" ]; then printf '%s\0' "$f"; fi
		done >"$LIST"
else
	# Not a git checkout (e.g. a downloaded zip): take the folders, minus
	# anything that could be a secret or a build leftover.
	for d in .dockerignore proto server web deploy; do
		[ -e "$ROOT/$d" ] || fail "$ROOT/$d is missing."
		printf '%s\0' "$d" >>"$LIST"
	done
fi
count="$(tr -cd '\0' <"$LIST" | wc -c | tr -d ' ')"
[ "$count" -gt 0 ] || fail "found no files to send."

TAR_OPTS=()
# macOS tar: no AppleDouble "._" files, extended attributes or Mac metadata.
export COPYFILE_DISABLE=1
for opt in --no-mac-metadata --no-xattrs; do
	if tar "$opt" -cf /dev/null -C "$WORK" files >/dev/null 2>&1; then TAR_OPTS+=("$opt"); fi
done
tar -czf "$WORK/upload.tgz" -C "$ROOT" ${TAR_OPTS[@]+"${TAR_OPTS[@]}"} \
	--exclude=node_modules --exclude=.DS_Store --exclude='.env' --exclude='.env.[!e]*' \
	--exclude='*.key' --exclude='*.pem' --exclude='*.p12' --exclude='*.p8' \
	--exclude=secrets --exclude=deploy/turnserver.conf --exclude=web/dist \
	--null -T "$LIST"
size_kb="$(($(wc -c <"$WORK/upload.tgz") / 1024))"
say "    $count files, ${size_kb} KB (code version $REV)"

# ---- 3. copy ----
say "3/5 Copying it to the server ..."
"${SSH[@]}" "${SUDO}sh -c 'umask 077 && cat > /opt/heartfulness-remote.upload.tgz'" <"$WORK/upload.tgz" ||
	fail "copying to the server failed (is the disk full?)."

# ---- 4. install + provision (runs as root on the server) ----
say "4/5 Setting up the server (first time: about 10 minutes; later: 2-3) ..."
cat >"$WORK/remote.sh" <<'REMOTE'
set -euo pipefail
DOMAIN=$1 EXTERNAL_IP=$2 REV=$3 ACME_EMAIL=${4:-}
DST=/opt/heartfulness-remote
UPLOAD=/opt/heartfulness-remote.upload.tgz
command -v flock >/dev/null || { echo "flock is missing on the server" >&2; exit 1; }
# Do not swap the files under a running setup or weekly rebuild.
exec 9>/run/heartfulness-remote.lock
flock -w 3600 9 || { echo "Another setup or rebuild is still running; try again later." >&2; exit 1; }
NEW="$(mktemp -d /opt/.heartfulness-remote.new.XXXXXX)"
tar -xzf "$UPLOAD" -C "$NEW" --no-same-owner --warning=no-unknown-keyword
rm -f "$UPLOAD"
printf '%s\n' "$REV" >"$NEW/.source-rev"
# Keep this server's own secrets and generated configuration.
for f in deploy/.env deploy/turnserver.conf; do
	if [ -f "$DST/$f" ]; then cp -p "$DST/$f" "$NEW/$f"; fi
done
if [ -d "$DST/.git" ]; then
	echo "    Note: this server was installed from GitHub; from now on update it with this script (deploy/update.sh no longer applies)."
fi
chmod 755 "$NEW"
OLD=""
if [ -d "$DST" ]; then
	OLD="$(mktemp -d /opt/.heartfulness-remote.old.XXXXXX)"
	mv "$DST" "$OLD/"
fi
mv "$NEW" "$DST"
if [ -n "$OLD" ]; then rm -rf -- "$OLD"; fi
exec 9>&- # provision.sh takes the same lock
export ACME_EMAIL
exec bash "$DST/deploy/provision.sh" "$DOMAIN" "$EXTERNAL_IP"
REMOTE
# The arguments were validated above and contain no quote characters.
if ! "${SSH[@]}" "${SUDO}bash -s -- '$DOMAIN' '$SERVER_IP' '$REV' '$ACME_EMAIL'" <"$WORK/remote.sh"; then
	fail "setup on the server did not finish (see the lines above).
  Fix the cause and run this script again; it is safe to repeat.
  Full details on the server: /var/log/heartfulness-remote-provision.log"
fi

# ---- 5. wait for HTTPS ----
resolve_a() {
	if command -v dig >/dev/null 2>&1; then
		dig +short A "$1" 2>/dev/null | grep -E '^[0-9.]+$' | tr '\n' ' '
	elif command -v host >/dev/null 2>&1; then
		host -t A "$1" 2>/dev/null | awk '/has address/ {printf "%s ", $NF}'
	fi
}
dns="$(resolve_a "$DOMAIN" || true)"
case " $dns " in
*" $SERVER_IP "*) ;;
"  ")
	say "    Note: $DOMAIN does not point anywhere yet. Point it at $SERVER_IP"
	say "    (on duckdns.org: type the IP next to your name and press \"update ip\")."
	;;
*)
	say "    Note: $DOMAIN points to ${dns% } but the server is $SERVER_IP. Update it"
	say "    (on duckdns.org: type $SERVER_IP next to your name and press \"update ip\")."
	;;
esac
say "5/5 Waiting for https://$DOMAIN to answer with a valid certificate (up to $WAIT_MINUTES minutes) ..."
deadline=$((SECONDS + WAIT_MINUTES * 60))
while :; do
	# --resolve talks to this server even if this computer's DNS is not updated yet.
	if curl -fsS --max-time 10 --resolve "$DOMAIN:443:$SERVER_IP" "https://$DOMAIN/healthz" >/dev/null 2>&1; then
		say ""
		say "Done. Heartfulness Remote is online at https://$DOMAIN"
		say "Open that address on the Mac (or follow the Mac app's setup) to finish."
		exit 0
	fi
	if [ "$SECONDS" -ge "$deadline" ]; then
		say ""
		say "The server is set up, but https://$DOMAIN does not answer yet."
		say "  - Usually the address does not point at $SERVER_IP yet; fix that and"
		say "    wait a few minutes: the certificate is requested again automatically."
		say "  - Status on the server: ssh $SSH_USER@$SERVER_IP tail /var/log/heartfulness-remote-setup.log"
		exit 3
	fi
	sleep 10
done
