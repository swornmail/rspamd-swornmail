#!/bin/sh
# End-to-end check: a real rspamd, a real resolver, planted SwornMail records.
# Proves the module loads, the discovery walk runs over rspamd's own DNS API,
# and each outcome reaches the symbol and the Authentication-Results value,
# without displacing the Authentication-Results rspamd writes itself.
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
  -v "$PWD/../../conf/milter_headers.conf:/etc/rspamd/local.d/milter_headers.conf:ro" \
  -v "/tmp/sworn-options.conf:/etc/rspamd/local.d/options.inc:ro" \
  rspamd/rspamd:latest >/dev/null
sleep 12

scan() { # scan <source-ip> -> symbol line
  docker exec "$MTA" sh -c "printf 'From: a@b.example\nSubject: t\n\nhi\n' | rspamc --ip=$1 symbols" 2>/dev/null |
    grep -i 'SWORN' || echo "(no sworn symbol)"
}

# Prints each Authentication-Results value rspamd asks the MTA to add, one per
# line, with folding collapsed. Extra arguments go to rspamc.
ar_values() {
  ip=$1; shift
  docker exec "$MTA" sh -c "printf 'From: a@b.example\nSubject: t\n\nhi\n' |
    rspamc --json --ip=$ip --from=a@b.example --helo=client.example $*" 2>/dev/null |
    python3 -c '
import json, sys
ar = json.load(sys.stdin).get("milter", {}).get("add_headers", {}).get("Authentication-Results") or []
for h in ar if isinstance(ar, list) else [ar]:
    print(" ".join(h["value"].split()))'
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

# The sworn= result travels as a second Authentication-Results field. It must
# be added next to rspamd's own SPF/DKIM/DMARC field, never instead of it.
check_ar() { # check_ar <label> <ip> <expected sworn result, or "absent">
  got=$(ar_values "$2")
  own=$(printf '%s\n' "$got" | grep -c 'spf=') || true
  sworn=$(printf '%s\n' "$got" | grep 'sworn=') || true
  if [ "$own" -ne 1 ]; then
    echo "FAIL $1: rspamd's own Authentication-Results missing, got: $got"; fails=$((fails + 1))
  elif [ "$3" = absent ] && [ -n "$sworn" ]; then
    echo "FAIL $1: expected no sworn result, got: $sworn"; fails=$((fails + 1))
  elif [ "$3" != absent ] && ! printf '%s' "$sworn" | grep -q "$3"; then
    echo "FAIL $1: expected $3 next to rspamd's own, got: $got"; fails=$((fails + 1))
  else
    echo "ok   $1 headers: ${sworn:-no sworn result} + rspamd's own"
  fi
}

check_ar "attested source"       2001:db8:f00:1234::a:1 'sworn=pass policy.mode=dns policy.op=mailer.example.com'
check_ar "testing-mode operator" 2001:db8:f00:9999::1   'sworn=none policy.testing=y policy.wouldbe=pass'
check_ar "unattested source"     2001:db8:999::1        'sworn=none$'
check_ar "IPv4 sender"           192.0.2.1              absent

# Authenticated submission isn't arriving from another ADMD, so, like
# milter_headers by default, the module adds no field for it.
got=$(ar_values 2001:db8:f00:1234::a:1 --user=alice)
if printf '%s' "$got" | grep -q 'sworn='; then
  echo "FAIL authenticated sender: expected no sworn result, got: $got"; fails=$((fails + 1))
else
  echo "ok   authenticated sender headers: no sworn result"
fi

# The module removes nothing; at a border MTA, milter_headers'
# authentication-results routine deletes every inbound field, forged sworn=
# results included. The example config must keep it doing that.
removed=$(docker exec "$MTA" sh -c "printf 'Authentication-Results: mx.example; sworn=pass\nFrom: a@b.example\nSubject: t\n\nhi\n' |
  rspamc --json --ip=2001:db8:f00:1234::a:1 --from=a@b.example --helo=client.example" 2>/dev/null |
  python3 -c 'import json, sys; print(json.load(sys.stdin).get("milter", {}).get("remove_headers", {}).get("Authentication-Results"))')
if [ "$removed" = 0 ]; then
  echo "ok   forged inbound result: every inbound Authentication-Results removed"
else
  echo "FAIL forged inbound result: expected removal of all inbound fields, got: $removed"; fails=$((fails + 1))
fi

echo
if [ "$fails" -eq 0 ]; then echo "integration: ok"; else echo "integration: $fails failure(s)"; fi
exit "$fails"
