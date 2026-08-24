--[[
SwornMail Mode-1 (DNS-only) discovery.

The resolver is injected, so this runs unchanged inside rspamd, under a unit
test with canned answers, and under the cross-implementation differential
harness. It performs no rspamd calls of its own.

A resolver is a table with:
  txt(name)  -> results_table | nil, err
  ptr(ip)    -> results_table | nil, err
  aaaa(host) -> results_table | nil, err
where err is nil for a definite negative (NXDOMAIN/NODATA), or a string
describing a temporary failure. Results are arrays of strings; aaaa returns
address strings.

Outcome is one of: 'pass', 'none', 'temperror'. Testing mode is reported
separately from the outcome — a confirmed operator publishing t=y is reported
as none with the would-be result attached, never as pass, because it has not
accepted the accountability that pass asserts.
]]

local ip = require 'sworn.ip'
local record = require 'sworn.record'

local discovery = {}

-- Total DNS work for one connection. Exhaustion is a temporary error, not a
-- negative answer: a verifier that returned none on budget exhaustion would
-- let an attacker suppress attestation by padding the walk.
discovery.MAX_QUERIES = 10

-- Only these two lengths are queried in the reverse tree. Asking at other
-- lengths would let a sub-delegation claim space it does not hold.
local REVERSE_LENGTHS = { 64, 48 }

-- Candidates derived from a PTR hostname, and the label floor that keeps a
-- receiver without a public-suffix list from querying a registry domain.
local MAX_CANDIDATES = 5
local MIN_CANDIDATE_LABELS = 3

local function new_budget()
  return { spent = 0 }
end

--- spend consumes one query, or reports exhaustion.
local function spend(budget)
  if budget.spent >= discovery.MAX_QUERIES then return false end
  budget.spent = budget.spent + 1
  return true
end

--- candidate_domains yields the operator-domain candidates for a
--- forward-confirmed hostname: the hostname itself, then successive parents.
function discovery.candidate_domains(host, is_public_suffix)
  host = (host or ''):gsub('%.$', '')
  local out = {}
  local cur = host
  while cur ~= '' and #out < MAX_CANDIDATES do
    local labels = 0
    for _ in (cur .. '.'):gmatch('([^%.]*)%.') do labels = labels + 1 end
    if is_public_suffix then
      if is_public_suffix(cur) then break end
    elseif labels < MIN_CANDIDATE_LABELS then
      break
    end
    out[#out + 1] = cur
    if labels < 2 then break end
    cur = cur:match('^[^%.]*%.(.*)$') or ''
  end
  return out
end

--- confirm checks whether the source falls inside a prefix the candidate
--- publishes. Returns a result table, or nil plus 'temperror' / nil.
local function confirm(resolver, budget, domain, source)
  if not spend(budget) then return nil, 'temperror' end
  local txts, err = resolver.txt('_prefixes._sworn.' .. domain)
  if err then return nil, 'temperror' end
  if not txts then return nil, nil end

  local rec = record.select_sworn(txts)
  if not rec then return nil, nil end
  local policy = record.parse_policy(rec)
  if not policy then return nil, nil end -- malformed policy confirms nothing

  -- Longest matching prefix wins, mirroring the precedence receivers apply
  -- when several attestations cover one source.
  local best
  for _, p in ipairs(policy.prefixes) do
    if ip.contains(p.addr, p.bits, source) and (not best or p.bits > best.bits) then
      best = p
    end
  end
  if not best then return nil, nil end

  return {
    outcome = 'pass',
    operator = domain,
    unit = ip.format_prefix(ip.masked(source, policy.unit), policy.unit),
    mode = 'dns',
    testing = policy.testing,
  }
end

--- run performs discovery for a source address string.
--- Returns a table: {outcome='pass'|'none'|'temperror', operator, unit, mode,
--- testing, queries}.
function discovery.run(resolver, source_text, opts)
  opts = opts or {}
  local budget = new_budget()
  local none = function(outcome)
    return { outcome = outcome or 'none', queries = budget.spent }
  end

  local source = ip.parse(source_text)
  -- Mode 1 attests IPv6 space only, and an ineligible source is never inside
  -- an attested prefix. Neither is an error: there is simply nothing to find.
  if not source or not ip.eligible_source(source) then return none() end

  -- Step 1: reverse-tree pointer, more specific first.
  for _, bits in ipairs(REVERSE_LENGTHS) do
    local name = ip.reverse_name(ip.masked(source, bits), bits)
    if name then
      if not spend(budget) then return none('temperror') end
      local txts, err = resolver.txt(name)
      if err then return none('temperror') end
      if txts then
        local rec = record.select_sworn(txts)
        local domain = rec and record.parse_pointer(rec)
        if domain then
          local res, temp = confirm(resolver, budget, domain, source)
          if temp then return none('temperror') end
          if res then
            res.queries = budget.spent
            return res
          end
          -- A d= that does not confirm falls through to step 2: pointing at a
          -- domain that publishes no covering prefix confirms nothing.
        end
      end
    end
  end

  -- Step 2: forward-confirmed PTR candidates.
  local host = opts.verified_hostname
  if not host then
    if not spend(budget) then return none('temperror') end
    local ptrs, err = resolver.ptr(source_text)
    if err then return none('temperror') end
    if not ptrs or not ptrs[1] then return none() end
    host = (ptrs[1]):gsub('%.$', '')

    -- FCrDNS: the name must resolve back to the connecting address, or any
    -- host could name itself into an operator's domain.
    if not spend(budget) then return none('temperror') end
    local addrs, aerr = resolver.aaaa(host)
    if aerr then return none('temperror') end
    if not addrs then return none() end
    local confirmed = false
    for _, a in ipairs(addrs) do
      local parsed = ip.parse(a)
      if parsed and ip.equal(parsed, source) then
        confirmed = true
        break
      end
    end
    if not confirmed then return none() end
  end

  if not record.valid_domain(host) then return none() end

  for _, candidate in ipairs(discovery.candidate_domains(host, opts.is_public_suffix)) do
    local res, temp = confirm(resolver, budget, candidate, source)
    if temp then return none('temperror') end
    if res then
      res.queries = budget.spent
      return res
    end
  end
  return none()
end

return discovery
