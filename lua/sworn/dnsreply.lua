--[[
Reads one reply from rspamd's coroutine DNS API into the resolver contract
sworn.discovery expects: results, or nil plus a temporary-error string, or
nil, nil for a definite negative.

A DNS reply is untrusted input, and so is the way it arrived. Kept free of
rspamd calls, so each way a reply can go wrong is tested directly instead of
needing a resolver that misbehaves on demand.
]]

local dnsreply = {}

-- Error strings librdns reports for a definite negative answer. Anything else
-- is a temporary failure and must not be reported as "no attestation":
-- treating a resolver outage as a negative answer would let an attacker
-- suppress attestation by disrupting DNS.
local DEFINITE_NEGATIVE = {
  ['no records with this name'] = true,
  ['requested record is not found'] = true,
}

--- read takes the query kind ('txt', 'ptr' or 'aaaa') and the two values
--- rspamd_dns.request returned.
function dnsreply.read(kind, ok, results)
  if ok then
    -- A successful reply that is not a result table is not an answer of any
    -- kind. Passing it through let a nil read as "no such record", a
    -- definite negative; it is a temporary failure instead.
    if type(results) ~= 'table' then return nil, 'malformed reply' end
    -- rspamd retries a truncated UDP answer over TCP, and hands over the
    -- partial one, marked, when that retry cannot be made or is truncated
    -- too. A partial RRset can hold one of two v=SWORN1 records, which
    -- would then look like the only one, so it is a temporary failure and
    -- never an answer. Fails closed: no result, and nothing held against
    -- the sender.
    if results.truncated then return nil, 'truncated reply' end
    if kind == 'aaaa' then
      -- rspamd returns addresses as its own IP objects. Discovery compares
      -- address text, and without this every forward confirmation it does
      -- itself fails for a correctly configured sender.
      local out = {}
      for i, a in ipairs(results) do out[i] = tostring(a) end
      return out, nil
    end
    return results, nil
  end
  -- A nil first return means the request could not be scheduled at all
  -- (per-task DNS cap) — a resource limit, so temporary.
  if ok == nil then return nil, 'request not scheduled' end
  if type(results) == 'string' and DEFINITE_NEGATIVE[results] then return nil, nil end
  return nil, results or 'dns error'
end

return dnsreply
