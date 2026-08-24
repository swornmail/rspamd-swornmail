local t = require 'harness'
local record = require 'sworn.record'
local ip = require 'sworn.ip'

t.test('parses a policy record', function()
  local p = record.parse_policy('v=SWORN1; p=2001:db8:f00::/48,2620:12a:8000::/48; u=56; t=y; rua=mailto:a@b.example')
  t.ok(p ~= nil, 'parses')
  if not p then return end
  t.eq(#p.prefixes, 2, 'prefix count')
  t.eq(p.unit, 56, 'unit')
  t.eq(p.testing, true, 'testing')
  t.eq(p.rua, 'mailto:a@b.example', 'rua')
  t.eq(ip.format_prefix(p.prefixes[1].addr, p.prefixes[1].bits), '2001:db8:f00::/48', 'first prefix')
end)

t.test('applies defaults', function()
  local p = record.parse_policy('v=SWORN1; p=2001:db8:f00::/48')
  t.ok(p ~= nil, 'parses')
  if not p then return end
  t.eq(p.unit, 64, 'default unit')
  t.eq(p.testing, false, 'not testing by default')
  t.is_nil(p.rua, 'no rua')
end)

t.test('reads testing flags', function()
  for text, want in pairs({
    ['v=SWORN1; t=y'] = true,
    ['v=SWORN1; t=x:y'] = true,
    ['v=SWORN1; t=y:x'] = true,
    ['v=SWORN1; t=x'] = false,
    ['v=SWORN1; t='] = false,
    ['v=SWORN1; t=yes'] = false,
  }) do
    local p = record.parse_policy(text)
    t.ok(p ~= nil, 'parses ' .. text)
    if p then t.eq(p.testing, want, 'testing for ' .. text) end
  end
end)

t.test('rejects malformed policy records', function()
  for _, bad in ipairs({
    '',
    'p=2001:db8:f00::/48; v=SWORN1',        -- v must be first
    ';u=64; v=SWORN1',                      -- and a leading ';' cannot smuggle a tag ahead
    ';;; p=2001:db8:f00::/48; v=SWORN1',
    'v=SWORN9; p=2001:db8:f00::/48',        -- unknown version
    'v=SWORN1; u=64; u=48',                 -- duplicate tag
    'v=SWORN1; u=0',                        -- unit below range
    'v=SWORN1; u=65',                       -- unit above range
    'v=SWORN1; u=-1',
    'v=SWORN1; u=abc',
    'v=SWORN1; p=2001:db8::/16',            -- prefix shorter than the floor
    'v=SWORN1; p=2001:db8:f00::1/48',       -- not masked
    'v=SWORN1; p=fd00::/48',                -- outside global unicast
    'v=SWORN1; p=2002:db8::/48',            -- 6to4
    'v=SWORN1; rua=https://evil.example',   -- only mailto: is defined
    'v=SWORN1; rua=',
    'v=SWORN1; rua=mailto:',
    'v=SWORN1; p=2001:db8:f00::/48 extra',  -- whitespace inside a value
    'v=SWORN1; noequals',
  }) do
    t.is_nil(record.parse_policy(bad), 'reject ' .. bad)
  end
end)

t.test('allows a leading empty segment before v', function()
  local p = record.parse_policy(';v=SWORN1; p=2001:db8:f00::/48')
  t.ok(p ~= nil and #p.prefixes == 1, 'leading semicolon is not itself an error')
end)

t.test('ignores unknown tags and prefixes past the cap', function()
  local p = record.parse_policy('v=SWORN1; p=2001:db8:f00::/48; future=whatever')
  t.ok(p ~= nil and #p.prefixes == 1, 'unknown tag ignored')

  local list = {}
  for i = 1, record.MAX_PREFIXES + 5 do
    list[#list + 1] = string.format('2001:db8:%x::/48', i)
  end
  local capped = record.parse_policy('v=SWORN1; p=' .. table.concat(list, ','))
  t.ok(capped ~= nil, 'over-long list still parses')
  if capped then t.eq(#capped.prefixes, record.MAX_PREFIXES, 'capped at the limit') end
end)

t.test('parses pointer records', function()
  t.eq(record.parse_pointer('v=SWORN1; d=mailer.example.com'), 'mailer.example.com', 'pointer domain')
  for _, bad in ipairs({
    'v=SWORN1', 'd=mailer.example.com', 'v=SWORN1; d=', 'v=SWORN9; d=x.example.com',
    'v=SWORN1; d=mailer..example.com', 'v=SWORN1; d=-bad.example.com',
    'v=SWORN1; d=*.example.com',
  }) do
    t.is_nil(record.parse_pointer(bad), 'reject pointer ' .. bad)
  end
end)

t.test('validates operator domains', function()
  for _, good in ipairs({ 'example.com', 'a.b.c.example.com', 'xn--bcher-kva.example' }) do
    t.ok(record.valid_domain(good), 'accept ' .. good)
  end
  for _, bad in ipairs({
    '', 'exa mple.com', 'exa\r\nmple.com', '-bad.example', 'bad-.example',
    'a..b', '*.example.com', string.rep('a', 64) .. '.example',
  }) do
    t.ok(not record.valid_domain(bad), 'reject domain ' .. tostring(bad))
  end
end)

t.test('selects exactly one v=SWORN1 record', function()
  t.eq(record.select_sworn({ 'v=SWORN1; d=a.example', 'unrelated' }), 'v=SWORN1; d=a.example', 'single record')
  -- Two candidate records are ambiguous: picking one would let whichever the
  -- resolver ordered first decide the outcome.
  t.is_nil(record.select_sworn({ 'v=SWORN1; d=a.example', 'v=SWORN1; d=b.example' }), 'two records')
  t.is_nil(record.select_sworn({ 'other' }), 'no record')
  t.is_nil(record.select_sworn({}), 'empty set')
end)

os.exit(t.report('sworn.record'))
