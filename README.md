# rspamd-swornmail

An [rspamd](https://rspamd.com) module implementing **SwornMail Mode 1**:
DNS-only IPv6 prefix attestation. For each connecting IPv6 address it finds
the operator accountable for that address — if one has published the records —
and reports it as a symbol and an `Authentication-Results` entry.

Protocol: [github.com/swornmail/spec](https://github.com/swornmail/spec).

**Informational by default.** Every symbol scores `0.0`, so installing this
module cannot change a single verdict until you deliberately give the symbols
weight. It never rejects mail, and a failed check never counts against a
sender — SwornMail is fail-open by design, because absence of attestation must
not be worse than the status quo.

## What it gives you

A stable reputation key for IPv6 senders. An operator publishing SwornMail
records is saying "this prefix is one accountable entity, staked on our
domain" — so instead of reputation on a single address out of 2^64, you get
reputation on `(operator domain, observed /64)`, widening to the attested unit
only where you hold independent evidence of control (see "Reputation
semantics" below).

```
Authentication-Results: mx.example.com; sworn=pass policy.mode=dns
    policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64"
    policy.observed="2001:db8:f00:1234::/64"
```

## Requirements

- rspamd 3.x or later (developed against 4.1, integration-tested against
  4.2.2). Prefer 3.2 or later: 3.0 and 3.1 can't tell the module that a DNS
  answer was truncated; see [Limitations](#limitations)
- Senders reaching you over IPv6 — Mode 1 attests IPv6 space only
- A working resolver; the module spends at most 10 DNS queries per connection

## Install

Four pieces: the module, the protocol library it uses, a config section, and
a `milter_headers` config that removes forged results.

```sh
install -d /etc/rspamd/plugins.d /etc/rspamd/lua/sworn
install -m 0644 swornmail.lua   /etc/rspamd/plugins.d/swornmail.lua
install -m 0644 lua/sworn/*.lua /etc/rspamd/lua/sworn/
```

Then declare the config section. **This step is required** — rspamd disables a
Lua module that has no configuration, and `local.d/<module>.conf` is only
merged for modules that ship a `modules.d` stub, which a third-party module
does not. Add to `/etc/rspamd/rspamd.conf.local`:

```ucl
swornmail {
  enabled = true;
  lib_path = "/etc/rspamd/lua";
}
```

rspamd's stock config doesn't remove inbound `Authentication-Results` fields,
so a forged `sworn=pass` would reach your users' mailboxes. If you don't have
`/etc/rspamd/local.d/milter_headers.conf` yet, install the example:

```sh
install -m 0644 conf/milter_headers.conf /etc/rspamd/local.d/milter_headers.conf
```

If you already have one, merge in its settings; see
[Removing forged results](#removing-forged-results).

Restart rspamd. You should see, once, at startup:

```
swornmail: Mode-1 attestation enabled, authserv-id mx.example.com
```

and no line starting `swornmail: forged sworn= results can reach mailboxes`.
If one shows up, it names the `milter_headers` setting to fix.

Check it end to end against a sender you know publishes records:

```sh
printf 'From: a@b.example\nSubject: t\n\nhi\n' |
  rspamc --ip=2001:db8:f00:1234::a:1 symbols | grep SWORN
```

## Configuration

All settings, with their defaults:

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Set false to disable without uninstalling |
| `lib_path` | `/etc/rspamd/lua` | Where `sworn/*.lua` was installed |
| `authserv_id` | this host's name | Identity stamped in `Authentication-Results` |
| `use_mta_hostname` | `false` | Take the client hostname in the scan request as forward-confirmed (see below) |
| `ineligible_prefixes` | `[]` | IPv6 prefixes never matched to an operator. **If rspamd sees IPv4 clients through NAT64 or SIIT, list the translation prefix**: every translated client appears inside it. A malformed entry disables the module, with an error in the log |
| `symbol_pass` | `SWORN_PASS` | Symbol for a confirmed operator |
| `symbol_testing` | `SWORN_TESTING` | Symbol for an operator still in testing mode |
| `symbol_none` | `SWORN_NONE` | No attestation found |
| `symbol_temperror` | `SWORN_TEMPERROR` | DNS failure or query budget exhausted |

By default the module does its own rDNS check: it looks up the PTR of the
connecting address and confirms that the name resolves back to it. That costs
two of the ten queries.

Those two queries can change a result, not only add to its cost. A walk that
fitted in ten queries with the MTA's hostname can need more without it, and a
walk that needs an eleventh query ends in `temperror`. For example: both
reverse pointers name domains whose policies do not cover the source, and the
fifth candidate from the hostname publishes one that does. With the MTA's
hostname that is nine queries and a pass. With the module's own check it is
eleven, so the result is `temperror`.

`use_mta_hostname = true` skips both and takes the client hostname the scan
request carries instead. rspamd does not check that name. Whoever sends the
scan request picks it, so the setting is only safe when every client of the
scan API is an MTA of yours that reports a name only after forward-confirming
it. Postfix is documented to: otherwise it reports `unknown`, and the module
then falls back to its own check, as it does for a bracketed address. Leave
it off if anything else can reach rspamd's scan
port, or if you are unsure what your MTA reports. A name alone never produces
a pass: the domain it leads to still has to publish a prefix covering the
connecting address.

With the setting on, the module reads the name from the scan request itself.
When the MTA supplies none, rspamd looks up the PTR on its own without
forward-confirming it, and that name is never treated as verified.

This setting used to default to `true`. If you relied on that, set it
explicitly.

## Symbols

| Symbol | Meaning |
|---|---|
| `SWORN_PASS` | An operator has attested this address. Options: `<operator>:<declared unit>`, then `observed=<observed unit>` |
| `SWORN_TESTING` | An operator attested it but publishes `t=y` — observe-only, **stake nothing**. Same options |
| `SWORN_NONE` | No attestation covers this address |
| `SWORN_TEMPERROR` | DNS failed, or the 10-query budget ran out |

```
SWORN_PASS (0.00)[mailer.example.com:2001:db8:f00::/48, observed=2001:db8:f00:1234::/64]
```

The first option is the unit the operator declared, the second the `/64` this
connection came from. They are `policy.unit` and `policy.observed` in the
header, and "Reputation semantics" below says which one to key on. The first
option is unchanged from earlier versions, which carried only that one.

All default to `0.0`. To act on results, give them weight in
`/etc/rspamd/local.d/groups.conf` — but read "Reputation semantics" below
first, because the protocol constrains what you may do with a failure.

## Authentication-Results

rspamd's built-in AR generator has a fixed method list (spf, dkim, dmarc, arc)
and no way to register another, so the `sworn=` result is emitted as a
**second** `Authentication-Results` field. RFC 8601 §4 explicitly permits more
than one, and consumers parse them all.

The module adds that field itself, and adds nothing for local or
authenticated senders: their mail isn't arriving from another ADMD.

Earlier versions of this README had you add a `sworn-ar` custom routine to
`milter_headers.conf`. Remove it. `milter_headers` lets a custom routine's
output replace the field its own routine queued under the same name, so that
setup silently dropped rspamd's SPF, DKIM and DMARC results.

### Removing forged results

Anyone upstream can write `Authentication-Results: mx.example.com; sworn=pass`
into a message. A border MTA has to remove fields claiming its own
authserv-id (RFC 8601 §5), or nothing downstream can tell the forged field
from yours.

The module removes nothing itself. `milter_headers`' `authentication-results`
routine does that: it deletes every inbound `Authentication-Results` field
before rspamd adds its own, which also deals with forged SPF, DKIM and DMARC
results. rspamd's stock config doesn't turn the routine on, and when it is on
it skips authenticated and local senders. The example
[`conf/milter_headers.conf`](conf/milter_headers.conf) covers both:

```ucl
use = ["authentication-results"];
authenticated_headers = ["authentication-results"];
local_headers = ["authentication-results"];

routines {
  authentication-results {
    add_smtp_user = false;
  }
}
```

- `authenticated_headers`: without it, anyone with a stolen password can send
  your local users a forged `sworn=pass`.
- `local_headers`: rspamd counts private and loopback addresses as local, and
  behind a proxy or NAT that's every connection. If rspamd sits behind
  another MTA of yours whose results you rely on, those are deleted too.
- `add_smtp_user = false`: covering authenticated senders also puts rspamd's
  own field on the mail they send out, and by default that field names their
  login (`smtp.auth=alice`).

To check it, send rspamd a forged field as an authenticated sender:

```sh
printf 'Authentication-Results: mx.example.com; sworn=pass\nFrom: a@b.example\n\nhi\n' |
  rspamc --json --ip=2001:db8::1 --user=alice --from=alice@example.com |
  grep -A11 '"milter"'
```

```
    "milter": {
        "add_headers": {
            "Authentication-Results": {
                "order": 1,
                "value": "mx.example.com;\n\tauth=pass smtp.mailfrom=alice@example.com"
            }
        },
        "remove_headers": {
            "X-Spam": 0,
            "Authentication-Results": 0
        }
    },
```

Key order can differ between runs. `"Authentication-Results": 0` tells the
MTA to delete every inbound field of that name, and the field rspamd adds
doesn't name the login. Without the example config, `remove_headers` has no
`Authentication-Results` entry.

At startup the module reads the `milter_headers` config and logs a warning
for each setting there that lets a forged result through, for example:

```
swornmail: forged sworn= results can reach mailboxes: forged results from authenticated senders are kept; add authentication-results to authenticated_headers
```

That includes a routine listed after `authentication-results` in `use` that
resets the removal for the same header name, such as `remove-headers` with
`"Authentication-Results" = 1`. `milter_headers` keeps one removal instruction
per header name and the last routine to set it wins, so that would keep every
forged field but the first.

The check goes by the instruction left after the last routine, so a routine
that narrows the removal is not reported when a later one sets it back to `0`.
It works that out for authenticated and local senders separately: a routine
that sets the removal back counts only for the senders it is not skipped for,
and only if it does so for every message.

It can't see per-message overrides from the settings module, which can turn
the routine off at runtime, or what a `custom` routine removes, since that is
decided by the routine's code for each message.

Don't narrow the deletion with `remove_ar_from`. It matches only a plain name
at the start of the field, so a forged `(c) mx.example; sworn=pass` or
`"mx.example"; sworn=pass` isn't recognised and survives (checked against
rspamd 4.2.2).

### Testing mode in the header

An operator publishing `t=y` has **not** accepted accountability yet. Such a
result is reported as `none`, carrying the result it would have had:

```
Authentication-Results: mx.example.com; sworn=none policy.testing=y
    policy.wouldbe=pass policy.mode=dns policy.op=trial.example.com
    policy.unit="2001:db8:f00:9999::/64"
    policy.observed="2001:db8:f00:9999::/64"
```

Treating that as a pass would stake reputation — credit *and* blame — that the
operator explicitly declined. Anything consuming these headers must key on
`sworn=pass`, not on the presence of `policy.op`.

## Security notes

**Strip inbound results at the trust boundary.** An `Authentication-Results`
field claiming your own authserv-id is trivially forged by anyone upstream and
must not survive into your ADMD (RFC 8601 §5). rspamd's stock config doesn't
remove it; use the example `milter_headers` config, which deletes every
inbound field for every sender. See
[Removing forged results](#removing-forged-results).

**Failures never count against a sender.** `sworn=fail`, `temperror`, and
`permerror` all identify *no accountable party*, so the protocol forbids
treating them as worse than `none`. Do not give the failure symbols positive
weight. A DNS outage must not become a deliverability incident.

**Temporary DNS failure is not a negative answer.** The module distinguishes
NXDOMAIN from SERVFAIL/timeout and reports the latter as `temperror`. Reading
an outage as "no attestation" would let anyone suppress attestation by
disrupting DNS.

**Bounded work per connection.** At most 10 DNS queries, after which the
result is `temperror`. A DNS answer rspamd marks as truncated is `temperror`
as well: part of a record set could hide a second, conflicting record.
Records are parsed strictly: a malformed record, or two
`v=SWORN1` records at one name, confirms nothing rather than being guessed at.
The declared unit must be at least as specific as every enumerated prefix, so
a reputation unit can never extend into space the operator did not attest.

**Reputation semantics.** On `sworn=pass`, key reputation on
`(operator domain, observed unit)`. The module emits two prefixes:
`policy.unit` is the aggregation the publisher asked for, and
`policy.observed` is the source `/64` this connection actually corroborated,
computed from the connection rather than from the record. A signed broad
prefix is not proof that a shared-hosting tenant controls the provider
aggregate, so apply consequences to `policy.observed` unless you hold
independent evidence of a wider control boundary. The symbol carries both as
well, the observed unit as its `observed=` option. Do not attribute a *failed*
result to the domain named in it.

## Testing

```sh
./run-tests.sh              # unit tests (any Lua 5.1+/LuaJIT, or Docker)
./test/integration/run.sh   # real rspamd + real resolver + planted records
```

The unit suite covers the address arithmetic, record parsing, the discovery
walk with an injected resolver, the reading of rspamd's DNS replies, header
rendering, and the startup check of the `milter_headers` config. The
integration test stands up rspamd and CoreDNS in containers and asserts each
outcome reaches the right symbol and header, that rDNS is confirmed over
rspamd's own resolver, what `use_mta_hostname` does and does not believe, and
that the example `milter_headers` config removes forged results from remote,
authenticated and local senders. Both run in CI.

The integration test pins rspamd by digest. To try another release:

```sh
RSPAMD_IMAGE=rspamd/rspamd:latest ./test/integration/run.sh
```

This module is a **third implementation** of rules the Go and Rust verifiers
already enforce, so it is also driven by a differential harness — every record
and prefix decision is compared against the Go reference, and any disagreement
is a bug:

```sh
cd ../swornmail-go && go run ./cmd/recorddiff --arm /path/to/lua-arm.sh
```

## Limitations

- **Mode 1 only.** Mode-2 connection tokens (COSE/Ed25519) are not implemented
  here; a milter runs after the SMTP command phase, and token verification
  lives in the Go and Rust implementations.
- **IPv6 only**, by protocol design.
- **No DNSSEC validation** — the module trusts its resolver. Absent DNSSEC,
  an active attacker able to replace the discovery and policy answers can
  impersonate an operator. Use a validating resolver where that threat is in
  scope.
- **A NUL octet in a TXT record is not seen.** The protocol rejects a record
  holding any octet outside printable ASCII, and the module does that for
  every octet it is given. rspamd hands it TXT data cut off at the first NUL
  octet, though, so `<valid record>` + NUL + anything reaches the module as
  the valid record alone and is accepted (checked against rspamd 4.2.2). A
  verifier that sees the whole record rejects it. Only someone who controls
  the zone or the answers can publish such a record, and they could publish
  the valid part on its own, so it gains them nothing new; but this module
  accepts a record that others refuse.
- **Truncated answers on rspamd 3.0 and 3.1.** From 3.2, rspamd retries a
  truncated UDP answer over TCP and tells the module when all it has is a
  partial one, which the module reports as `temperror`. 3.0 and 3.1 do
  neither, so a partial record set is read as if it were complete.

## License

Apache-2.0 (see `LICENSE`). Copyright: see `NOTICE`.
