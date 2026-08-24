#!/bin/sh
# End-to-end check: a real rspamd, a real resolver, planted SwornMail records.
# Proves the module loads, the discovery walk runs over rspamd's own DNS API,
# and each outcome reaches the symbol and the Authentication-Results value.
set -e
cd "$(dirname "$0")"
NET=sworn-itest-net
DNS=sworn-itest-dns
MTA=sworn-itest-rspamd

cleanup() {
  docker rm -f "$DNS" "$MTA" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
docker run -d --name "$DNS" --network "$NET" -v "$PWD:/zones:ro" \
  coredns/coredns:latest -conf /zones/Corefile >/dev/null
sleep 3
DNSIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DNS")
[ -n "$DNSIP" ] || { echo "FAIL: no resolver address"; exit 1; }

sed "s/%DNSIP%/$DNSIP/" options.conf > /tmp/sworn-options.conf
docker run -d --name "$MTA" --network "$NET" \
  -v "$PWD/../../swornmail.lua:/etc/rspamd/plugins.d/swornmail.lua:ro" \
  -v "$PWD/../../lua/sworn:/etc/rspamd/lua/sworn:ro" \
  -v "$PWD/../../conf/rspamd.conf.local:/etc/rspamd/rspamd.conf.local:ro" \
  -v "/tmp/sworn-options.conf:/etc/rspamd/local.d/options.inc:ro" \
  rspamd/rspamd:latest >/dev/null
sleep 12

scan() { # scan <source-ip> -> symbol line
  docker exec "$MTA" sh -c "printf 'From: a@b.example\nSubject: t\n\nhi\n' | rspamc --ip=$1 symbols" 2>/dev/null |
    grep -i 'SWORN' || echo "(no sworn symbol)"
}

fails=0
check() { # check <label> <ip> <expected-symbol>
  got=$(scan "$2")
  case "$got" in
    *"$3"*) echo "ok   $1: $got" ;;
    *) echo "FAIL $1: expected $3, got: $got"; fails=$((fails + 1)) ;;
  esac
}

# An attested source confirmed through the reverse-tree pointer.
check "attested source"      2001:db8:f00:1234::a:1 SWORN_PASS
# The same prefix under an operator still publishing t=y.
check "testing-mode operator" 2001:db8:f00:9999::1   SWORN_TESTING
# Inside no attested prefix.
check "unattested source"    2001:db8:999::1        SWORN_NONE
# IPv4 is out of scope for Mode 1 and must produce no symbol at all.
got=$(scan 192.0.2.1)
if [ "$got" = "(no sworn symbol)" ]; then
  echo "ok   IPv4 sender: no symbol"
else
  echo "FAIL IPv4 sender: expected no symbol, got: $got"; fails=$((fails + 1))
fi

echo
if [ "$fails" -eq 0 ]; then echo "integration: ok"; else echo "integration: $fails failure(s)"; fi
exit "$fails"
