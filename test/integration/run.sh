#!/bin/sh
# End-to-end check: a real rspamd, a real resolver, planted SwornMail records.
# Proves the module loads, the discovery walk runs over rspamd's own DNS API,
# and each outcome reaches the symbol and the Authentication-Results value,
# without displacing the Authentication-Results rspamd writes itself. Also
# checks that the shipped milter_headers config removes forged inbound
# results from every kind of sender, and that a config which narrows that
# removal is reported at startup.
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
TRUST=sworn-itest-rspamd-trust-$$
OPTS=$(mktemp)
TRUSTCONF=$(mktemp)
NARROWED=$(mktemp)

cleanup() {
  docker rm -f "$DNS" "$MTA" "$STOCK" "$TRUST" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap 'cleanup; rm -f "$OPTS" "$TRUSTCONF" "$NARROWED"' EXIT
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

start_rspamd() { # start_rspamd <name> <module config> [docker run args]
  name=$1; conf=$2; shift 2
  docker run -d --name "$name" --network "$NET" \
    -v "$PWD/../../swornmail.lua:/etc/rspamd/plugins.d/swornmail.lua:ro" \
    -v "$PWD/../../lua/sworn:/etc/rspamd/lua/sworn:ro" \
    -v "$conf:/etc/rspamd/rspamd.conf.local:ro" \
    -v "$OPTS:/etc/rspamd/local.d/options.inc:ro" \
    "$@" "$RSPAMD_IMAGE" >/dev/null
}
start_rspamd "$MTA" "$PWD/../../conf/rspamd.conf.local" \
  -v "$PWD/../../conf/milter_headers.conf:/etc/rspamd/local.d/milter_headers.conf:ro"
# rspamd's stock milter_headers config runs no routines, so nothing removes
# forged results; the module has to say so at startup.
start_rspamd "$STOCK" "$PWD/../../conf/rspamd.conf.local"

# A third instance carries the two settings an operator has to choose on
# purpose. It trusts the hostname the scan client supplies, and its
# milter_headers config is the shipped one plus a later routine that narrows
# the removal of inbound results to the first field.
sed 's/use_mta_hostname = false/use_mta_hostname = true/' ../../conf/rspamd.conf.local > "$TRUSTCONF"
grep -q 'use_mta_hostname = true' "$TRUSTCONF" || { echo "FAIL: could not turn use_mta_hostname on"; exit 1; }
cat > "$NARROWED" <<'CONF'
use = ["authentication-results", "remove-headers"];
authenticated_headers = ["authentication-results", "remove-headers"];
local_headers = ["authentication-results", "remove-headers"];
routines {
  authentication-results { add_smtp_user = false; }
  remove-headers { headers { "Authentication-Results" = 1; } }
}
CONF
chmod 644 "$TRUSTCONF" "$NARROWED"
start_rspamd "$TRUST" "$TRUSTCONF" \
  -v "$NARROWED:/etc/rspamd/local.d/milter_headers.conf:ro"

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
wait_ready "$TRUST"

scan_in() { # scan_in <container> <source-ip> [rspamc args] -> symbol line
  c=$1; ip=$2; shift 2
  docker exec "$c" sh -c "printf 'From: a@b.example\nSubject: t\n\nhi\n' | rspamc --ip=$ip $* symbols" 2>/dev/null |
    grep -i 'SWORN' || echo "(no sworn symbol)"
}
scan() { scan_in "$MTA" "$@"; } # scan <source-ip> [rspamc args]

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
check_in() { # check_in <container> <label> <ip> <expected-symbol> [rspamc args]
  c=$1; label=$2; ip=$3; want=$4; shift 4
  got=$(scan_in "$c" "$ip" "$@")
  case "$got" in
    *"$want"*) echo "ok   $label: $got" ;;
    *) echo "FAIL $label: expected $want, got: $got"; fails=$((fails + 1)) ;;
  esac
}
check() { # check <label> <ip> <expected-symbol> [rspamc args]
  label=$1; ip=$2; want=$3; shift 3
  check_in "$MTA" "$label" "$ip" "$want" "$@"
}

# An attested source confirmed through the reverse-tree pointer.
check "attested source"      2001:db8:f00:1234::a:1 SWORN_PASS
# The same prefix under an operator still publishing t=y.
check "testing-mode operator" 2001:db8:f00:9999::1   SWORN_TESTING
# Inside no attested prefix.
check "unattested source"    2001:db8:999::1        SWORN_NONE

# No reverse-tree pointer and no hostname from the scan client, so discovery
# resolves the PTR and forward-confirms it over rspamd's own resolver.
check "operator found through rDNS" 2001:db8:abc:1::25 'SWORN_PASS (0.00)[fcrdns.example.net:'
# The symbol carries the unit the operator declared and, as a second option,
# the /64 this connection came from, so the two cannot be mistaken.
check "declared and observed unit" 2001:db8:abc:1::25 \
  '[fcrdns.example.net:2001:db8:abc::/48, observed=2001:db8:abc:1::/64]'
# A host naming itself into an operator's domain: its PTR points there, but
# the name resolves to another address, so nothing is confirmed.
check "PTR that does not forward-confirm" 2001:db8:abc:2::25 SWORN_NONE

# The scan client chooses the hostname it reports, so by default it is not
# believed: this source has no PTR, and claiming the operator's host name
# for it gets nothing.
check "claimed hostname, default config" 2001:db8:abc:3::25 SWORN_NONE --hostname=mx1.fcrdns.example.net
# The same goes for a claim that contradicts the source's real rDNS.
check "claimed hostname against real rDNS" 2001:db8:abc:2::25 SWORN_NONE --hostname=mx1.fcrdns.example.net
# With use_mta_hostname on, the operator has said the scan client only
# reports forward-confirmed names, and the claim is taken as given.
check_in "$TRUST" "claimed hostname, use_mta_hostname on" 2001:db8:abc:3::25 \
  'SWORN_PASS (0.00)[fcrdns.example.net:' --hostname=mx1.fcrdns.example.net
# Without a claim that instance confirms rDNS itself, as the default does.
check_in "$TRUST" "no hostname, use_mta_hostname on" 2001:db8:abc:1::25 'SWORN_PASS (0.00)[fcrdns.example.net:'
# rspamd looks up the PTR on its own when the scan client names no host, and
# does not forward-confirm it. That name is not the scan client's word, so it
# is not believed even here: the host naming itself into the operator's
# domain still gets nothing, whether the client says nothing or says what an
# MTA says when its own check failed.
check_in "$TRUST" "unconfirmed PTR, use_mta_hostname on" 2001:db8:abc:2::25 SWORN_NONE
check_in "$TRUST" "unconfirmed PTR, client reports unknown" 2001:db8:abc:2::25 SWORN_NONE --hostname=unknown
check_in "$TRUST" "unconfirmed PTR, client reports an address" 2001:db8:abc:2::25 SWORN_NONE "--hostname=[2001:db8:abc:2::25]"

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
# A later routine that resets the removal to "first field only" lets a second
# forged field through; the module has to name it at startup.
if docker logs "$TRUST" 2>&1 | grep "$WARNING" | grep -q 'remove-headers'; then
  echo "ok   narrowed config: warns that remove-headers keeps inbound results"
else
  echo "FAIL narrowed config: expected a stripping warning naming remove-headers"; fails=$((fails + 1))
fi
removed=$(docker exec "$TRUST" sh -c "printf 'Authentication-Results: mx.example; sworn=pass\nAuthentication-Results: mx.example; sworn=pass\nFrom: a@b.example\nSubject: t\n\nhi\n' |
  rspamc --json --ip=2001:db8:f00:1234::a:1 --from=a@b.example --helo=client.example" 2>/dev/null |
  python3 -c 'import json, sys; print(json.load(sys.stdin).get("milter", {}).get("remove_headers", {}).get("Authentication-Results"))')
if [ "$removed" = 1 ]; then
  echo "ok   narrowed config: rspamd asks for only the first inbound field to be removed"
else
  echo "FAIL narrowed config: expected the removal to be narrowed to 1, got: $removed"; fails=$((fails + 1))
fi

echo
if [ "$fails" -eq 0 ]; then echo "integration: ok"; else echo "integration: $fails failure(s)"; fi
exit "$fails"
