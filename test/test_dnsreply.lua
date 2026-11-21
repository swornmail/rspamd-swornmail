local t = require 'harness'
local dnsreply = require 'sworn.dnsreply'

local A = 'v=SWORN1; p=2001:db8:f00::/48; u=64'

--- addr stands in for rspamd's IP object: not a string, but prints as one.
local function addr(text)
  return setmetatable({}, { __tostring = function() return text end })
end

t.test('passes a complete answer through', function()
  local reply = { A, truncated = false, authenticated = false }
  local got, err = dnsreply.read('txt', true, reply)
  t.is_nil(err, 'no error')
  t.eq(got[1], A, 'record text')
  t.eq(#got, 1, 'one record')
  -- rspamd before 3.2 sets no truncated field at all.
  got, err = dnsreply.read('ptr', true, { 'mx1.mailer.example.com' })
  t.is_nil(err, 'no error without the field')
  t.eq(got[1], 'mx1.mailer.example.com', 'PTR name')
end)

-- A resolver that cannot retry over TCP hands over a partial RRset. With two
-- competing v=SWORN1 records published, the partial answer shows one of them
-- as the only one, and whoever can force truncation picks which.
t.test('a truncated reply is a temporary error, never an answer', function()
  for _, kind in ipairs({ 'txt', 'ptr', 'aaaa' }) do
    local got, err = dnsreply.read(kind, true, { A, truncated = true })
    t.is_nil(got, kind .. ': no results from a truncated reply')
    t.ok(type(err) == 'string' and err ~= '', kind .. ': reported as temporary')
  end
  local got, err = dnsreply.read('txt', true, { truncated = true })
  t.is_nil(got, 'an empty truncated reply is not a negative answer')
  t.ok(err ~= nil, 'an empty truncated reply is temporary')
end)

-- A reply reported as successful but carrying no result table must not be
-- read as "no such record": that is a definite negative, and a resolver
-- glitch would then erase an attestation.
t.test('a successful reply without a result table is a temporary error', function()
  for _, results in ipairs({ false, 'text', 7 }) do
    local got, err = dnsreply.read('txt', true, results)
    t.is_nil(got, 'no results from ' .. type(results))
    t.ok(type(err) == 'string' and err ~= '', type(results) .. ': reported as temporary')
  end
  local got, err = dnsreply.read('txt', true, nil)
  t.is_nil(got, 'no results from nil')
  t.ok(type(err) == 'string' and err ~= '', 'nil: reported as temporary')
end)

-- Discovery compares address text. Handed rspamd's IP objects it matched
-- nothing, and every forward confirmation it did itself came back none.
t.test('AAAA answers become address strings', function()
  local got, err = dnsreply.read('aaaa', true, { addr('2001:db8:abc:1::25'), addr('2001:db8:abc:1::26'), truncated = false })
  t.is_nil(err, 'no error')
  t.eq(#got, 2, 'both addresses')
  t.eq(type(got[1]), 'string', 'a string, not an object')
  t.eq(got[1], '2001:db8:abc:1::25', 'first address')
  t.eq(got[2], '2001:db8:abc:1::26', 'second address')
end)

t.test('tells a definite negative from a temporary failure', function()
  for _, msg in ipairs({ 'no records with this name', 'requested record is not found' }) do
    local got, err = dnsreply.read('txt', false, msg)
    t.is_nil(got, msg .. ': no results')
    t.is_nil(err, msg .. ': a definite negative carries no error')
  end
  -- Reading an outage as "no attestation" would let anyone who can disrupt
  -- DNS erase an operator's standing.
  for _, msg in ipairs({ 'server fail', 'timeout', 'network error', 'query refused', 'something new' }) do
    local got, err = dnsreply.read('txt', false, msg)
    t.is_nil(got, msg .. ': no results')
    t.eq(err, msg, msg .. ': temporary')
  end
  local got, err = dnsreply.read('txt', false, nil)
  t.is_nil(got, 'failure without a reason: no results')
  t.ok(err ~= nil, 'failure without a reason is temporary')
  -- The request was never sent: rspamd's per-task DNS cap.
  got, err = dnsreply.read('txt', nil, nil)
  t.is_nil(got, 'unscheduled: no results')
  t.ok(err ~= nil, 'unscheduled is temporary')
end)

os.exit(t.report('sworn.dnsreply'))
