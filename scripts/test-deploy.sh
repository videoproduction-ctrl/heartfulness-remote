#!/usr/bin/env bash
# Automated checks of the server deployment files (run by the CI "docker" job;
# also runs on any Linux machine with Docker, as root or a docker-group user).
#
#   1. deploy/docker-compose.yml validates with a generated dummy .env, and
#      only the server container receives the TURN secret.
#   2. coturn (the exact image pinned in docker-compose.yml) starts with
#      deploy/turnserver.conf.template rendered the way provision.sh renders
#      it, with the compose hardening, and logs no configuration warnings.
#   3. TURN REST credentials computed like server/internal/server/turn_link.go
#      are accepted and wrong ones refused.
#   4. Relaying to private/reserved addresses (loopback, 0.0.0.0, RFC 1918,
#      CGNAT, link-local metadata, the Docker network, multicast) is refused
#      and relaying to a public address is allowed (a deny list that blocks
#      everything, e.g. "denied-peer-ip=::-::", fails this test).
#
# Uses host networking for coturn (UDP/TCP 3478 and 49160-49200 must be free).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/hr-test-deploy.XXXXXX")"
NAME="hr-test-deploy-coturn-$$"
cleanup() {
	docker container rm --force "$NAME" >/dev/null 2>&1 || true
	rm -rf -- "$T"
}
trap cleanup EXIT
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
ok() { echo "ok   $*"; }

COTURN_IMAGE="$(sed -n 's/^[[:space:]]*image:[[:space:]]*\([^[:space:]#]*coturn[^[:space:]#]*\).*/\1/p' "$ROOT/deploy/docker-compose.yml" | head -n 1)"
[ -n "$COTURN_IMAGE" ] || fail "no coturn image found in deploy/docker-compose.yml"
echo "coturn image: $COTURN_IMAGE"

# ---- 1. compose file ----
mkdir -p "$T/deploy"
cp -r "$ROOT/deploy/." "$T/deploy/"
rm -f "$T/deploy/.env" "$T/deploy/turnserver.conf"
SECRET="$(openssl rand -hex 32)"
EXT_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
[ -n "$EXT_IP" ] || fail "could not find this machine's IPv4 address"
(
	umask 077
	printf 'HR_DOMAIN=hr.test\nHR_ORIGIN=https://hr.test\nHR_TURN_SECRET=%s\nHR_EXTERNAL_IP=%s\nACME_EMAIL=\nHR_HOST_PUBKEY=\n' \
		"$SECRET" "$EXT_IP" >"$T/deploy/.env"
	# Same rendering as deploy/provision.sh.
	sed -e "s|@HR_TURN_SECRET@|$SECRET|g" -e "s|@HR_DOMAIN@|hr.test|g" -e "s|@HR_EXTERNAL_IP@|$EXT_IP|g" \
		"$T/deploy/turnserver.conf.template" >"$T/deploy/turnserver.conf"
)
chmod 644 "$T/deploy/turnserver.conf" # readable by coturn's "nobody" in this test
if grep -q '@[A-Z_]*@' "$T/deploy/turnserver.conf"; then fail "unrendered placeholder in turnserver.conf"; fi
docker compose --project-name hr-test-deploy -f "$T/deploy/docker-compose.yml" --env-file "$T/deploy/.env" \
	config >"$T/compose.out" || fail "docker compose config"
ok "docker compose config"
# The secret must reach the server only (caddy and coturn get no env_file).
n="$(grep -c -F "$SECRET" "$T/compose.out" || true)"
[ "$n" = 1 ] || fail "TURN secret appears $n times in the resolved compose config (want 1: server)"
ok "TURN secret only in the server's environment"

# ---- 2. coturn starts cleanly ----
docker run -d --name "$NAME" --network host --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE \
	--security-opt no-new-privileges:true --tmpfs /tmp --tmpfs /var/lib/coturn \
	-v "$T/deploy/turnserver.conf:/etc/coturn/turnserver.conf:ro" --entrypoint turnserver \
	"$COTURN_IMAGE" -c /etc/coturn/turnserver.conf >/dev/null
sleep 3
[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || {
	docker logs "$NAME" 2>&1 | tail -n 20
	fail "coturn exited at startup"
}
if docker logs "$NAME" 2>&1 | grep -i -E 'Bad configuration|deprecated|CONFIG ERROR|unknown option|invalid option'; then
	fail "coturn reported configuration problems (above)"
fi
ok "coturn starts without configuration warnings"

# ---- 3./4. credentials and peers ----
user="$(($(date +%s) + 86400)):hr"
cred="$(printf '%s' "$user" | openssl dgst -sha1 -hmac "$SECRET" -binary | base64)"
uclient() { # uclient <password> <peer>
	timeout 30 docker run --rm --network host --entrypoint turnutils_uclient "$COTURN_IMAGE" \
		-u "$user" -w "$1" -e "$2" -n 2 -m 1 -c "$EXT_IP" 2>&1 || true
}
out="$(uclient "AAAAwrongAAAA=" 1.1.1.1)"
grep -q "Cannot complete Allocation" <<<"$out" || fail "wrong TURN credentials were not refused"
ok "wrong TURN credentials refused"
out="$(uclient "$cred" 1.1.1.1)"
if grep -q -E "error 40[13]|Cannot complete Allocation" <<<"$out" || ! grep -q "Total transmit time" <<<"$out"; then
	echo "$out" | tail -n 15
	fail "relaying to a public address (1.1.1.1) did not work"
fi
ok "valid credentials: allocation + relay to a public address allowed"
for peer in 127.0.0.1 0.0.0.0 10.1.2.3 172.30.77.2 192.168.1.1 100.64.0.1 169.254.169.254 224.0.0.1; do
	out="$(uclient "$cred" "$peer")"
	grep -q "error 403" <<<"$out" || {
		echo "$out" | tail -n 15
		fail "relaying to $peer was not refused"
	}
done
ok "relaying to private/reserved addresses refused"
echo "all deployment checks passed"
