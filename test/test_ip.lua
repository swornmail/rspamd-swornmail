local t = require 'harness'
local ip = require 'sworn.ip'

local function parse_ok(s)
  local a = ip.parse(s)
  t.ok(a ~= nil, 'parse ' .. s)
  return a
end

t.test('parses the canonical forms', function()
  for text, want in pairs({
    ['2001:db8:f00:1234::a:1'] = '2001:db8:f00:1234::a:1',
    ['2001:0db8:0f00::0001'] = '2001:db8:f00::1',
    ['::1'] = '::1',
    ['::'] = '::',
    ['2001:db8::'] = '2001:db8::',
    ['fe80::1'] = 'fe80::1',
    ['::ffff:192.0.2.1'] = '::ffff:c000:201',
    ['2001:DB8::1'] = '2001:db8::1',
    -- One zero group is written out; only a run of two or more becomes '::'.
    ['2001:db8:0:1:1:1:1:1'] = '2001:db8:0:1:1:1:1:1',
    ['1:0:0:2:0:0:0:3'] = '1:0:0:2::3',
  }) do
    local a = parse_ok(text)
    if a then t.eq(ip.format(a), want, 'format ' .. text) end
  end
end)

t.test('rejects malformed addresses', function()
  for _, bad in ipairs({
    '', '::1::2', '2001:db8', '2001:db8:::1', '1:2:3:4:5:6:7:8:9',
    'gggg::1', '2001:db8::1%eth0', '[2001:db8::1]', '2001:db8::12345',
    '1.2.3.4', '::ffff:1.2.3', '::ffff:256.0.0.1', '::ffff:1.2.3.04',
    ':1:2:3:4:5:6:7', '1:2:3:4:5:6:7:', '2001:db8::1:',
  }) do
    t.is_nil(ip.parse(bad), 'reject ' .. bad)
  end
end)

t.test('masks addresses', function()
  local a = parse_ok('2001:db8:f00:1234::a:1')
  t.eq(ip.format(ip.masked(a, 64)), '2001:db8:f00:1234::', 'mask /64')
  t.eq(ip.format(ip.masked(a, 48)), '2001:db8:f00::', 'mask /48')
  t.eq(ip.format(ip.masked(a, 32)), '2001:db8::', 'mask /32')
  t.eq(ip.format(ip.masked(a, 0)), '::', 'mask /0')
  t.eq(ip.format(ip.masked(a, 128)), '2001:db8:f00:1234::a:1', 'mask /128')
  -- A non-byte-aligned length must clear only the low bits of the split byte.
  local b = parse_ok('2001:dbf::')
  t.eq(ip.format(ip.masked(b, 28)), '2001:db0::', 'mask /28')
end)

t.test('tests containment', function()
  local pfx = parse_ok('2001:db8:f00::')
  t.ok(ip.contains(pfx, 48, parse_ok('2001:db8:f00:1234::25')), 'inside /48')
  t.ok(not ip.contains(pfx, 48, parse_ok('2001:db8:f01::25')), 'outside /48')
  -- The boundary addresses of the range are inside it.
  t.ok(ip.contains(pfx, 48, parse_ok('2001:db8:f00::')), 'first address')
  t.ok(ip.contains(pfx, 48, parse_ok('2001:db8:f00:ffff:ffff:ffff:ffff:ffff')), 'last address')
end)

t.test('validates attestable prefixes', function()
  local cases = {
    { '2001:db8:f00::', 48, true, 'ordinary /48' },
    { '2001:db8::', 32, true, 'floor length' },
    { '2001:db8:f00:1234::', 64, true, 'ceiling length' },
    { '2001:db8::', 31, false, 'shorter than /32' },
    { '2001:db8:f00:1234::', 65, false, 'longer than /64' },
    { '2001:db8:f00::1', 48, false, 'not masked' },
    { 'fd00::', 48, false, 'ULA, outside 2000::/3' },
    { 'fe80::', 48, false, 'link-local' },
    { '::ffff:0:0', 96, false, 'IPv4-mapped' },
    { '2001:0:1::', 48, false, 'Teredo' },
    { '2002:db8::', 48, false, '6to4' },
  }
  for _, c in ipairs(cases) do
    local a = parse_ok(c[1])
    t.eq(ip.valid_prefix(a, c[2]), c[3], c[4])
  end
end)

t.test('judges source eligibility', function()
  for _, c in ipairs({
    { '2001:db8:f00::25', true }, { '2001:db8::1', true },
    { 'fd00::1', false }, { 'fe80::1', false }, { 'ff02::1', false },
    { '::1', false }, { '::ffff:192.0.2.1', false }, { '64:ff9b::1', false },
    { '2001::1', false }, { '2002::1', false },
  }) do
    t.eq(ip.eligible_source(parse_ok(c[1])), c[2], 'eligible ' .. c[1])
  end
end)

t.test('parses prefixes from record text', function()
  local a, bits = ip.parse_prefix('2001:db8:f00::/48')
  t.ok(a ~= nil and bits == 48, 'good prefix')
  for _, bad in ipairs({
    '2001:db8:f00::', '2001:db8:f00::/', '/48', '2001:db8:f00::/48/48',
    '2001:db8:f00::/129', '2001:db8:f00::/048', '2001:db8:f00::/4x',
    'nonsense/48',
  }) do
    t.is_nil(ip.parse_prefix(bad), 'reject prefix ' .. bad)
  end
end)

t.test('builds reverse-tree names', function()
  local a = parse_ok('2001:db8:f00:1234::a:1')
  t.eq(ip.reverse_name(ip.masked(a, 64), 64),
    '_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa', '/64 name')
  t.eq(ip.reverse_name(ip.masked(a, 48), 48),
    '_sworn.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa', '/48 name')
  t.is_nil(ip.reverse_name(a, 50), 'non-nibble length')
end)

os.exit(t.report('sworn.ip'))
