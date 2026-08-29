local t = require 'harness'
local authres = require 'sworn.authres'

local PASS = { outcome = 'pass', operator = 'mailer.example.com', unit = '2001:db8:f00:1234::/64', observed = '2001:db8:f00:1234::/64', mode = 'dns', testing = false }
-- A publisher declaring a coarse unit over shared space: the header must still
-- carry the /64 this connection corroborated, so a consumer reading only the
-- header cannot widen where reputation lands.
local COARSE = { outcome = 'pass', operator = 'tenant.example', unit = '2001:db8::/32', observed = '2001:db8:f00:1234::/64', mode = 'dns', testing = false }
local OBSERVING = { outcome = 'pass', operator = 'mailer.example.com', unit = '2001:db8:f00:1234::/64', observed = '2001:db8:f00:1234::/64', mode = 'dns', testing = true }

t.test('renders each outcome exactly as the Go reference does', function()
  t.eq(authres.render('mx.example.net', PASS),
    'mx.example.net; sworn=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"',
    'pass')
  t.eq(authres.render('mx.example.net', OBSERVING),
    'mx.example.net; sworn=none policy.testing=y policy.wouldbe=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"',
    'testing')
  t.eq(authres.render('mx.example.net', { outcome = 'temperror' }), 'mx.example.net; sworn=temperror', 'temperror')
  t.eq(authres.render('mx.example.net', { outcome = 'none' }), 'mx.example.net; sworn=none', 'none')
  t.eq(authres.render('mx.example.net', nil), 'mx.example.net; sworn=none', 'missing result')
end)

t.test('never reports a testing operator as passing', function()
  local rendered = authres.render('mx.example.net', OBSERVING)
  t.ok(not rendered:find('sworn=pass', 1, true), 'no sworn=pass for a testing operator')
  t.ok(rendered:find('policy.testing=y', 1, true) ~= nil, 'carries policy.testing')
  t.ok(rendered:find('policy.wouldbe=pass', 1, true) ~= nil, 'carries the would-be result')
end)

t.test('quotes the unit', function()
  -- A prefix contains ':' and '/', which RFC 8601 requires be quoted.
  t.ok(authres.render('mx', PASS):find('policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"', 1, true) ~= nil, 'quoted unit')
  t.eq(authres.render('mx', COARSE),
    'mx; sworn=pass policy.mode=dns policy.op=tenant.example policy.unit="2001:db8::/32" policy.observed="2001:db8:f00:1234::/64"',
    'a coarse declared unit still reports the observed /64')
end)

t.test('classifies outcomes for symbol selection', function()
  t.eq(authres.kind(PASS), 'pass', 'pass')
  t.eq(authres.kind(OBSERVING), 'testing', 'testing is never pass')
  t.eq(authres.kind({ outcome = 'temperror' }), 'temperror', 'temperror')
  t.eq(authres.kind({ outcome = 'none' }), 'none', 'none')
  t.eq(authres.kind(nil), 'none', 'missing result')
end)

os.exit(t.report('sworn.authres'))
