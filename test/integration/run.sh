#!/bin/sh
# End-to-end check: a real rspamd, a real resolver, planted SwornMail records.
# Proves the module loads, the discovery walk runs over rspamd's own DNS API,
# and each outcome reaches the symbol and the Authentication-Results value,
# without displacing the Authentication-Results rspamd writes itself. Also
# checks that the shipped milter_headers config removes forged inbound
# results from every kind of sender.
set -e
cd "$(dirname "$0")"

# Pinned by digest so every run, CI included, tests the same images. To try
# another release: RSPAMD_IMAGE=rspamd/rspamd:latest ./test/integration/run.sh
RSPAMD_IMAGE=${RSPAMD_IMAGE:-rspamd/rspamd@sha256:c1cd5850358a3564a60c00e7ad5668d4b9a7a61b271e2b9068b2e66f4303f611} # 4.2.2
COREDNS_IMAGE=${COREDNS_IMAGE:-coredns/coredns@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286}

# Per-run names, so two runs on one machine don't remove each other's
# containers.
NET=sworn-itest-net-$$
DNS=sworn-itest-dns-$$
MTA=sworn-itest-rspamd-$$
STOCK=sworn-itest-rspamd-stock-$$
OPTS=$(mktemp)

cleanup() {
  docker rm -f "$DNS" "$MTA" "$STOCK" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap 'cleanup; rm -f "$OPTS"' EXIT
cleanup

docker network create "$NET" >/dev/null
docker run -d --name "$DNS" --network "$NET" -v "$PWD:/zones:ro" \
  "$COREDNS_IMAGE" -conf /zones/Corefile >/dev/null
sleep 3
DNSIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DNS")
[ -n "$DNSIP" ] || { echo "FAIL: no resolver address"; exit 1; }

sed "s/%DNSIP%/$DNSIP/" options.conf > "$OPTS"
# mktemp makes it owner-only, and rspamd runs as its own user.
chmod 644 "$OPTS"

start_rspamd() { # start_rspamd <name> [docker run args]
  name=$1; shift
  docker run -d --name "$name" --network "$NET" \
    -v "$PWD/../../swornmail.lua:/etc/rspamd/plugins.d/swornmail.lua:ro" \
    -v "$PWD/../../lua/sworn:/etc/rspamd/lua/sworn:ro" \
    -v "$PWD/../../conf/rspamd.conf.local:/etc/rspamd/rspamd.conf.local:ro" \
    -v "$OPTS:/etc/rspamd/local.d/options.inc:ro" \
    "$@" "$RSPAMD_IMAGE" >/dev/null
}
start_rspamd "$MTA" \
  -v "$PWD/../../conf/milter_headers.conf:/etc/rspamd/local.d/milter_headers.conf:ro"
# rspamd's stock milter_headers config runs no routines, so nothing removes
# forged results; the module has to say so at startup.
start_rspamd "$STOCK"

wait_ready() { # wait_ready <container>
  for _ in $(seq 60); do
    if docker exec "$1" sh -c "printf 'Subject: t\n\nhi\n' | rspamc symbols" 2>/dev/null | grep -q '^Action'; then
      return 0
    fi
    sleep 1
  done
  echo "FAIL: $1 never answered a scan"
  docker logs "$1" 2>&1 | tail -20
  exit 1
}
wait_ready "$MTA"
wait_ready "$STOCK"

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

# Authenticated submission isn't arriving from another ADMD, so the module
# adds no field for it. rspamd does add its own now, because the shipped
# config covers authenticated senders, and that one goes out with their
# outbound mail: it must not name the login.
got=$(ar_values 2001:db8:f00:1234::a:1 --user=alice)
if printf '%s' "$got" | grep -q 'sworn='; then
  echo "FAIL authenticated sender: expected no sworn result, got: $got"; fails=$((fails + 1))
elif printf '%s' "$got" | grep -q -e 'alice' -e 'smtp.auth='; then
  echo "FAIL authenticated sender: login name in Authentication-Results: $got"; fails=$((fails + 1))
else
  echo "ok   authenticated sender headers: no sworn result, no login name"
fi

# The module removes nothing; milter_headers' authentication-results routine
# deletes every inbound field, forged sworn= results included. It skips
# authenticated and local senders unless configured not to, and the shipped
# config says not to: a compromised account could otherwise forge sworn=pass
# for local recipients, and behind a proxy every connection looks local.
check_stripped() { # check_stripped <label> <ip> [rspamc args]
  label=$1; ip=$2; shift 2
  removed=$(docker exec "$MTA" sh -c "printf 'Authentication-Results: mx.example; sworn=pass\nFrom: a@b.example\nSubject: t\n\nhi\n' |
    rspamc --json --ip=$ip --from=a@b.example --helo=client.example $*" 2>/dev/null |
    python3 -c 'import json, sys; print(json.load(sys.stdin).get("milter", {}).get("remove_headers", {}).get("Authentication-Results"))')
  if [ "$removed" = 0 ]; then
    echo "ok   forged inbound result, $label: every inbound Authentication-Results removed"
  else
    echo "FAIL forged inbound result, $label: expected removal of all inbound fields, got: $removed"; fails=$((fails + 1))
  fi
}
check_stripped "remote sender"        2001:db8:f00:1234::a:1
check_stripped "authenticated sender" 2001:db8:f00:1234::a:1 --user=alice
check_stripped "local sender"         10.0.0.5

# The startup warning for a config that keeps forged results. The shipped
# config must not trigger it, and the stock one must.
WARNING='forged sworn= results can reach mailboxes'
if docker logs "$MTA" 2>&1 | grep -q "$WARNING"; then
  echo "FAIL shipped config: startup warning: $(docker logs "$MTA" 2>&1 | grep "$WARNING" | head -1)"; fails=$((fails + 1))
else
  echo "ok   shipped config: no stripping warning at startup"
fi
if docker logs "$STOCK" 2>&1 | grep -q "$WARNING"; then
  echo "ok   stock config: warns that nothing removes forged results"
else
  echo "FAIL stock config: expected a stripping warning at startup"; fails=$((fails + 1))
fi

echo
if [ "$fails" -eq 0 ]; then echo "integration: ok"; else echo "integration: $fails failure(s)"; fi
exit "$fails"
