#!/usr/bin/env bash
# Da root della repo: sudo unshare --net -- bash tests/run_turn_tls_smoke.sh "$(command -v python)"
set -euo pipefail
umask 077
script=$(realpath "$0")
python=$(realpath -s "${1:?Indicare il percorso di Python con aiortc installato}")

if [[ "$(ip -o link show | awk -F': ' '{print $2}')" != "lo" ]]; then
  echo "Prova consentita solo in un namespace di rete con la sola interfaccia lo." >&2
  exit 2
fi
if [[ $EUID == 0 ]]; then
  if [[ "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ]]; then
    echo "Creare prima un namespace di rete dedicato con sudo unshare --net." >&2
    exit 2
  fi
  ip link set lo up
  account="${SUDO_USER:-nobody}"
  if [[ "$account" == root ]]; then account=nobody; fi
  exec runuser -u "$account" -- /bin/bash "$script" "$python"
fi

tmp=$(mktemp -d)
pid=
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$tmp/empty-trust"
openssl rand -hex 32 > "$tmp/secret"
for ca in ca unrelated; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj "/CN=RemoteDesk test $ca" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$tmp/$ca.key" -out "$tmp/$ca.crt" 2>/dev/null
done
openssl req -newkey rsa:2048 -nodes -subj '/CN=RemoteDesk TURN loopback' \
  -keyout "$tmp/server.key" -out "$tmp/server.csr" 2>/dev/null
cat > "$tmp/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EXT
openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" \
  -CAcreateserial -days 1 -sha256 -extfile "$tmp/server.ext" -out "$tmp/server.crt" 2>/dev/null

cat > "$tmp/turn.conf" <<CONF
listening-ip=127.0.0.1
relay-ip=127.0.0.1
tls-listening-port=15349
min-port=50000
max-port=50031
realm=remotedesk.test
use-auth-secret
static-auth-secret=$(cat "$tmp/secret")
cert=$tmp/server.crt
pkey=$tmp/server.key
pidfile=$tmp/turn.pid
userdb=$tmp/turn.sqlite
log-file=$tmp/turn.log
simple-log
no-stdout-log
no-udp
no-tcp
no-dtls
no-tcp-relay
no-tlsv1
no-tlsv1_1
no-multicast-peers
no-cli
cli-password=$(openssl rand -hex 32)
allow-loopback-peers
denied-peer-ip=0.0.0.0-255.255.255.255
allowed-peer-ip=127.0.0.1
relay-threads=1
total-quota=8
CONF
turnserver -c "$tmp/turn.conf" > "$tmp/server-output.log" 2>&1 &
pid=$!
timeout --kill-after=5s 90s "$python" "$(dirname "$script")/turn_tls_smoke.py" "$tmp"
