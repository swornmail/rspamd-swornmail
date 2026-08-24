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
reputation on `(operator domain, prefix)`.

```
Authentication-Results: mx.example.com; sworn=pass policy.mode=dns
    policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64"
```

## Requirements

- rspamd 3.x or later (developed and tested against 4.1)
- Senders reaching you over IPv6 — Mode 1 attests IPv6 space only
- A working resolver; the module spends at most 10 DNS queries per connection

## Install

Three pieces: the module, the protocol library it uses, and a config section.

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

Restart rspamd. You should see, once, at startup:

```
swornmail: Mode-1 attestation enabled, authserv-id mx.example.com
```

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
| `use_mta_hostname` | `true` | Trust the MTA's rDNS name (see below) |
| `mempool_variable` | `sworn_ar` | Where the AR value is left for `milter_headers` |
| `symbol_pass` | `SWORN_PASS` | Symbol for a confirmed operator |
| `symbol_testing` | `SWORN_TESTING` | Symbol for an operator still in testing mode |
| `symbol_none` | `SWORN_NONE` | No attestation found |
| `symbol_temperror` | `SWORN_TEMPERROR` | DNS failure or query budget exhausted |

`use_mta_hostname` is a query-budget optimisation. Under a Postfix milter the
hostname rspamd receives has already been forward-confirmed by the MTA, so
trusting it saves the PTR and forward-confirmation lookups. Set it to `false`
if rspamd receives mail from something whose rDNS handling you do not trust,
and the module will confirm rDNS itself.

## Symbols

| Symbol | Meaning |
|---|---|
| `SWORN_PASS` | An operator has attested this address. Option: `<operator>:<unit prefix>` |
| `SWORN_TESTING` | An operator attested it but publishes `t=y` — observe-only, **stake nothing** |
| `SWORN_NONE` | No attestation covers this address |
| `SWORN_TEMPERROR` | DNS failed, or the 10-query budget ran out |

All default to `0.0`. To act on results, give them weight in
`/etc/rspamd/local.d/groups.conf` — but read "Reputation semantics" below
first, because the protocol constrains what you may do with a failure.

## Authentication-Results

rspamd's built-in AR generator has a fixed method list (spf, dkim, dmarc, arc)
and no way to register another, so the `sworn=` result is emitted as a
**second** `Authentication-Results` field. RFC 8601 §4 explicitly permits more
than one, and consumers parse them all.

Add to `/etc/rspamd/local.d/milter_headers.conf`, merging `sworn-ar` into
whatever routines you already use:

```ucl
use = ["authentication-results", "sworn-ar"];

custom {
  sworn-ar = <<EOD
return function(task, common_meta)
  local value = task:get_mempool():get_variable('sworn_ar')
  if not value then
    return nil, {}, {}, common_meta
  end
  return nil, {['Authentication-Results'] = value}, {}, common_meta
end
EOD;
}
```

### Testing mode in the header

An operator publishing `t=y` has **not** accepted accountability yet. Such a
result is reported as `none`, carrying the result it would have had:

```
Authentication-Results: mx.example.com; sworn=none policy.testing=y
    policy.wouldbe=pass policy.mode=dns policy.op=trial.example.com
    policy.unit="2001:db8:f00:9999::/64"
```

Treating that as a pass would stake reputation — credit *and* blame — that the
operator explicitly declined. Anything consuming these headers must key on
`sworn=pass`, not on the presence of `policy.op`.

## Security notes

**Strip inbound results at the trust boundary.** An `Authentication-Results`
field claiming your own authserv-id is trivially forged by anyone upstream and
must not survive into your ADMD (RFC 8601 §5). rspamd can remove them for you
via `milter_headers`'s `remove_ar_from` setting — configure it with your own
hostnames if this rspamd is a border MTA.

**Failures never count against a sender.** `sworn=fail`, `temperror`, and
`permerror` all identify *no accountable party*, so the protocol forbids
treating them as worse than `none`. Do not give the failure symbols positive
weight. A DNS outage must not become a deliverability incident.

**Temporary DNS failure is not a negative answer.** The module distinguishes
NXDOMAIN from SERVFAIL/timeout and reports the latter as `temperror`. Reading
an outage as "no attestation" would let anyone suppress attestation by
disrupting DNS.

**Bounded work per connection.** At most 10 DNS queries, after which the
result is `temperror`. Records are parsed strictly: a malformed record, or two
`v=SWORN1` records at one name, confirms nothing rather than being guessed at.

**Reputation semantics.** On `sworn=pass`, key reputation on
`(operator domain, unit prefix)`. Abuse from an attested prefix should affect
that whole prefix — that is the point of attestation. Do not attribute a
*failed* result to the domain named in it.

## Testing

```sh
./run-tests.sh              # unit tests (any Lua 5.1+/LuaJIT, or Docker)
./test/integration/run.sh   # real rspamd + real resolver + planted records
```

The unit suite covers the address arithmetic, record parsing, the discovery
walk with an injected resolver, and header rendering. The integration test
stands up rspamd and CoreDNS in containers and asserts each outcome reaches
the right symbol.

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
  record spoofing yields at most denial of verification, never impersonation,
  because an attacker cannot also control the attested prefix.

## License

Apache-2.0 (see `LICENSE`). Copyright: see `NOTICE`.
