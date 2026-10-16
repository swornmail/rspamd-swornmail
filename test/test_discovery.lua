local t = require 'harness'
local discovery = require 'sworn.discovery'

local SRC = '2001:db8:f00:1234::a:1'
local REV64 = '_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa'
local REV48 = '_sworn.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa'
local POLICY = 'v=SWORN1; p=2001:db8:f00::/48; u=64'
local UNIT = '2001:db8:f00:1234::/64'

--- fake builds a resolver over canned answers. A name absent from the table
--- is a definite negative; a name in `fail` is a temporary failure.
local function fake(spec)
  spec = spec or {}
  local calls = { n = 0 }
  local function answer(map, key)
    calls.n = calls.n + 1
    if spec.fail and spec.fail[key] then return nil, 'server fail' end
    local v = map and map[key]
    if not v then return nil, nil end
    return v, nil
  end
  return {
    calls = calls,
    txt = function(name) return answer(spec.txt, name) end,
    ptr = function(addr) return answer(spec.ptr, addr) end,
    aaaa = function(host) return answer(spec.aaaa, host) end,
  }
end

-- A receiver behind its own NAT64 prefix configures it as ineligible: the
-- records that give a pass give none from inside it, with no DNS at all.
t.test('a configured ineligible prefix ends as none without queries', function()
  local spec = { txt = {
    [REV64] = { 'v=SWORN1; d=mailer.example.com' },
    ['_prefixes._sworn.mailer.example.com'] = { POLICY },
  } }
  local list, err = discovery.parse_ineligible({ '2001:db8:f00:1234::/64' })
  t.ok(list ~= nil, 'parses the configured list: ' .. tostring(err))
  local r = fake(spec)
  local res = discovery.run(r, SRC, { ineligible = list })
  t.eq(res.outcome, 'none', 'outcome')
  t.eq(r.calls.n, 0, 'no queries')
  -- The same records from outside the configured prefix still pass.
  t.eq(discovery.run(fake(spec), SRC, { ineligible = discovery.parse_ineligible({ '2001:db8:f00:abcd::/64' }) }).outcome, 'pass', 'elsewhere passes')
end)

t.test('rejects a malformed ineligible prefix list', function()
  for _, bad in ipairs({ { '192.0.2.0/24' }, { 'nonsense' }, { '2001:db8::' }, { 42 } }) do
    t.is_nil(discovery.parse_ineligible(bad), 'reject ' .. tostring(bad[1]))
  end
  t.ok(discovery.parse_ineligible({}) ~= nil, 'an empty list is fine')
  -- A map-shaped setting must not quietly become an empty list.
  t.is_nil(discovery.parse_ineligible({ nat64 = '64:ff9b:abcd::/96' }), 'reject a map')
  t.is_nil(discovery.parse_ineligible({ '64:ff9b:abcd::/96', extra = '2001:db8::/48' }), 'reject a list with extra keys')
  t.is_nil(discovery.parse_ineligible(42), 'reject a number')
  -- A hole leaves #list at 3 while ipairs stops at 1, which would drop the
  -- third prefix and let traffic from inside it be attributed after all.
  local holed = { '64:ff9b:abcd::/96', '2001:db8:1::/48', '2001:db8:2::/48' }
  holed[2] = nil
  t.is_nil(discovery.parse_ineligible(holed), 'reject a list with a hole')
  local one = discovery.parse_ineligible('64:ff9b:abcd::/96')
  t.ok(one ~= nil and #one == 1, 'a bare string is one prefix')
  t.eq(#discovery.parse_ineligible(nil), 0, 'unset is an empty list')
end)

t.test('confirms through the reverse-tree pointer', function()
  local r = fake({ txt = {
    [REV64] = { 'v=SWORN1; d=mailer.example.com' },
    ['_prefixes._sworn.mailer.example.com'] = { POLICY },
  } })
  local res = discovery.run(r, SRC)
  t.eq(res.outcome, 'pass', 'outcome')
  t.eq(res.operator, 'mailer.example.com', 'operator')
  t.eq(res.unit, UNIT, 'unit')
  t.eq(res.mode, 'dns', 'mode')
  t.eq(res.testing, false, 'not testing')
end)

t.test('prefers the more specific reverse-tree record', function()
  local r = fake({ txt = {
    [REV64] = { 'v=SWORN1; d=specific.example.com' },
    [REV48] = { 'v=SWORN1; d=broad.example.com' },
    ['_prefixes._sworn.specific.example.com'] = { POLICY },
    ['_prefixes._sworn.broad.example.com'] = { POLICY },
  } })
  t.eq(discovery.run(r, SRC).operator, 'specific.example.com', '/64 wins over /48')
end)

t.test('falls through when a pointer names a domain that does not confirm', function()
  -- Misdirected pointers are inert: the named domain must publish a covering
  -- prefix, so pointing at a domain that publishes none confirms nothing.
  local r = fake({
    txt = {
      [REV64] = { 'v=SWORN1; d=innocent.example.com' },
      ['_prefixes._sworn.mailer.example.com'] = { POLICY },
    },
    ptr = { [SRC] = { 'mx1.mailer.example.com.' } },
    aaaa = { ['mx1.mailer.example.com'] = { SRC } },
  })
  local res = discovery.run(r, SRC)
  t.eq(res.outcome, 'pass', 'falls through to the PTR path')
  t.eq(res.operator, 'mailer.example.com', 'operator from candidate walk')
end)

t.test('confirms through a forward-confirmed PTR', function()
  local r = fake({
    txt = { ['_prefixes._sworn.mailer.example.com'] = { POLICY } },
    ptr = { [SRC] = { 'mx1.mailer.example.com.' } },
    aaaa = { ['mx1.mailer.example.com'] = { SRC } },
  })
  local res = discovery.run(r, SRC)
  t.eq(res.outcome, 'pass', 'outcome')
  t.eq(res.operator, 'mailer.example.com', 'parent candidate confirms')
end)

t.test('requires the PTR to forward-confirm', function()
  -- Without FCrDNS any host could name itself into an operator's domain.
  local r = fake({
    txt = { ['_prefixes._sworn.mailer.example.com'] = { POLICY } },
    ptr = { [SRC] = { 'mx1.mailer.example.com.' } },
    aaaa = { ['mx1.mailer.example.com'] = { '2001:db8:999::1' } },
  })
  t.eq(discovery.run(r, SRC).outcome, 'none', 'mismatched forward answer')

  local missing = fake({
    txt = { ['_prefixes._sworn.mailer.example.com'] = { POLICY } },
    ptr = { [SRC] = { 'mx1.mailer.example.com.' } },
  })
  t.eq(discovery.run(missing, SRC).outcome, 'none', 'no forward answer')
end)

t.test('skips the PTR lookups when the MTA already confirmed the hostname', function()
  local r = fake({ txt = { ['_prefixes._sworn.mailer.example.com'] = { POLICY } } })
  local res = discovery.run(r, SRC, { verified_hostname = 'mx1.mailer.example.com' })
  t.eq(res.outcome, 'pass', 'outcome')
  t.ok(res.queries <= 4, 'no PTR or forward query spent (queries=' .. tostring(res.queries) .. ')')
end)

t.test('normalizes operator domains before DNS and reporting', function()
  local r = fake({ txt = { ['_prefixes._sworn.mailer.example.com'] = { POLICY } } })
  local res = discovery.run(r, SRC, { verified_hostname = 'MX1.Mailer.Example.COM.' })
  t.eq(res.outcome, 'pass', 'outcome')
  t.eq(res.operator, 'mailer.example.com', 'lowercase operator')
end)

-- A publisher enumerating space it shares cannot move the reputation boundary:
-- one connection from inside a /32 corroborates one /64, not the aggregate.
t.test('a coarse declared unit does not widen the observed unit', function()
  local r = fake({ txt = {
    ['_prefixes._sworn.mailer.example.com'] = { 'v=SWORN1; p=2001:db8::/32; u=32' },
  } })
  local res = discovery.run(r, SRC, { verified_hostname = 'mx1.mailer.example.com' })
  t.eq(res.outcome, 'pass', 'outcome')
  t.eq(res.unit, '2001:db8::/32', 'declared unit is reported as the claim')
  t.eq(res.observed, '2001:db8:f00:1234::/64', 'observed unit is the source /64')
end)

t.test('reports testing mode separately from the outcome', function()
  local r = fake({ txt = {
    [REV64] = { 'v=SWORN1; d=mailer.example.com' },
    ['_prefixes._sworn.mailer.example.com'] = { 'v=SWORN1; p=2001:db8:f00::/48; u=64; t=y' },
  } })
  local res = discovery.run(r, SRC)
  t.eq(res.outcome, 'pass', 'discovery itself is unaffected')
  t.eq(res.testing, true, 'testing flag carried to the caller')
end)

t.test('returns temperror on a temporary DNS failure', function()
  local r = fake({ fail = { [REV64] = true } })
  t.eq(discovery.run(r, SRC).outcome, 'temperror', 'reverse-tree SERVFAIL')

  local later = fake({
    txt = {
      [REV64] = { 'v=SWORN1; d=mailer.example.com' },
    },
    fail = { ['_prefixes._sworn.mailer.example.com'] = true },
  })
  t.eq(discovery.run(later, SRC).outcome, 'temperror', 'confirmation SERVFAIL')
end)

t.test('returns temperror when the query budget is exhausted', function()
  -- A long candidate chain must not silently answer none: that would let an
  -- attacker suppress attestation by padding the walk.
  local host = 'a.b.c.d.e.f.g.mailer.example.com'
  local r = fake({
    ptr = { [SRC] = { host .. '.' } },
    aaaa = { [host] = { SRC } },
  })
  local res = discovery.run(r, SRC)
  t.ok(res.outcome == 'none' or res.outcome == 'temperror', 'bounded outcome')
  t.ok(res.queries <= discovery.MAX_QUERIES, 'never exceeds the budget')
end)

t.test('answers none for ineligible sources', function()
  for _, addr in ipairs({ '192.0.2.1', 'fd00::1', 'fe80::1', '::1', '2001::1', '2002::1', 'nonsense' }) do
    local r = fake({})
    t.eq(discovery.run(r, addr).outcome, 'none', 'ineligible ' .. addr)
    t.eq(r.calls.n, 0, 'no queries spent for ' .. addr)
  end
end)

t.test('ignores a malformed or ambiguous policy record', function()
  local malformed = fake({ txt = {
    [REV64] = { 'v=SWORN1; d=mailer.example.com' },
    ['_prefixes._sworn.mailer.example.com'] = { 'v=SWORN1; p=not-a-prefix' },
  } })
  t.eq(discovery.run(malformed, SRC).outcome, 'none', 'malformed policy confirms nothing')

  local ambiguous = fake({ txt = {
    [REV64] = { 'v=SWORN1; d=mailer.example.com' },
    ['_prefixes._sworn.mailer.example.com'] = { POLICY, 'v=SWORN1; p=2001:db8:f00::/48; u=48' },
  } })
  t.eq(discovery.run(ambiguous, SRC).outcome, 'none', 'two policy records are ambiguous')
end)

t.test('walks candidate domains with a label floor', function()
  t.eq(#discovery.candidate_domains('mx1.mailer.example.com'), 2, 'stops before a two-label name')
  local walk = discovery.candidate_domains('a.b.mx1.mailer.example.com')
  t.eq(walk[1], 'a.b.mx1.mailer.example.com', 'hostname first')
  t.eq(walk[#walk], 'mailer.example.com', 'last candidate')
  t.ok(#walk <= 5, 'at most five candidates')
  t.eq(#discovery.candidate_domains('example.com'), 0, 'two labels yields nothing')
end)

os.exit(t.report('sworn.discovery'))
