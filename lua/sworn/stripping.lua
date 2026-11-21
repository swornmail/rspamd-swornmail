--[[
Checks that milter_headers will remove forged inbound Authentication-Results.

The module adds a sworn= field but removes nothing: at a border MTA that is
milter_headers' authentication-results routine's job. If the routine is off,
narrowed, or overridden by a routine that runs after it, a forged
"mx.example; sworn=pass" from upstream reaches the mailbox next to the real
result, and nothing in the message tells them apart. This can't be enforced
from here, so the module reports each gap at startup.

What a custom routine removes is decided by its code at scan time and cannot
be read from the config, so a custom routine that narrows the removal is not
reported unless it takes the authentication-results name itself.

Takes the milter_headers section as rspamd_config:get_all_opt returns it.
Kept free of rspamd calls so the rules can be tested directly.
]]

local stripping = {}

local AR = 'authentication-results'

local function lists(names, name)
  if type(names) ~= 'table' then return false end
  for _, v in ipairs(names) do
    if v == name then return true end
  end
  return false
end

--- run_order lists the routines milter_headers will run, in its order: the
--- four extended_spam_headers turns on, then use, each name once.
local function run_order(opts, use)
  local order, seen = {}, {}
  local function add(name)
    if type(name) == 'string' and not seen[name] then
      seen[name] = true
      order[#order + 1] = name
    end
  end
  if opts.extended_spam_headers then
    for _, name in ipairs({ 'x-spamd-result', 'x-rspamd-server', 'x-rspamd-queue-id', 'x-rspamd-action' }) do
      add(name)
    end
  end
  for _, name in ipairs(use) do add(name) end
  return order
end

--- later_removals returns what each routine running after
--- authentication-results asks to be removed under the same header name, as
--- a list of { routine, value }.
---
--- milter_headers collects removals in one table keyed by header name, and
--- every routine writes into it in turn. The last to write wins, so a later
--- routine replaces the "remove every field" that authentication-results
--- queued. A key spelled in another case is a separate entry and replaces
--- nothing, so only an exact match counts.
local function later_removals(opts, use, header)
  local routines = type(opts.routines) == 'table' and opts.routines or {}
  local out, after = {}, false
  for _, name in ipairs(run_order(opts, use)) do
    local r = type(routines[name]) == 'table' and routines[name] or {}
    local listed = type(r.headers) == 'table' and r.headers[header] ~= nil
    if name == AR then
      after = true
    elseif after then
      -- A routine that ran earlier doesn't matter: authentication-results
      -- overwrote whatever it queued.
      if name == 'remove-headers' then
        if listed then out[#out + 1] = { name, r.headers[header] } end
      elseif name == 'add-headers' then
        -- Queues its own remove setting, 0 unless changed, for each header
        -- it adds.
        if listed then out[#out + 1] = { name, r.remove == nil and 0 or r.remove } end
      elseif r.header == header and r.remove then
        -- Every other built-in routine removes its own header, which is
        -- this one only if it was renamed to it. A false remove queues
        -- nothing.
        out[#out + 1] = { name, r.remove }
      end
    end
  end
  return out
end

--- gaps returns one message per way a forged result would survive, or an
--- empty list when every inbound Authentication-Results field is removed for
--- every sender.
function stripping.gaps(opts)
  if type(opts) ~= 'table' then
    return { 'milter_headers is not configured, so nothing removes forged inbound Authentication-Results' }
  end
  if opts.enabled == false then
    return { 'milter_headers is disabled, so nothing removes forged inbound Authentication-Results' }
  end
  -- milter_headers only runs routines listed in use, which may also be a
  -- single name.
  local use = type(opts.use) == 'string' and { opts.use } or opts.use
  if not lists(use, AR) then
    return { "milter_headers doesn't list authentication-results in use, so forged inbound results are kept" }
  end

  local gaps = {}
  -- Checked after the per-sender lists, so it skips the routine for everyone.
  if opts.skip_all == true then
    table.insert(gaps, 'milter_headers has skip_all set, so no sender gets inbound results removed')
  end
  -- A custom routine runs instead of the built-in one with the same name.
  if type(opts.custom) == 'table' and opts.custom[AR] ~= nil then
    table.insert(gaps,
      'a custom routine named authentication-results replaces the built-in one, which removes inbound results')
  end
  local r = type(opts.routines) == 'table' and type(opts.routines[AR]) == 'table' and opts.routines[AR] or {}
  -- 0 removes every field of that name. A positive number removes only that
  -- one, so a second forged field survives, and false removes none.
  if r.remove ~= nil and r.remove ~= 0 then
    table.insert(gaps, string.format(
      'authentication-results has remove = %s, which keeps some inbound fields; leave it at 0', tostring(r.remove)))
  end
  -- Its matcher reads only a plain name at the start of the field, so a
  -- forged "(c) mx.example; sworn=pass" or a quoted authserv-id gets through.
  if r.remove_ar_from ~= nil then
    table.insert(gaps,
      'authentication-results has remove_ar_from set, which misses forged fields that start with a comment or quotes')
  end
  if r.header ~= nil and tostring(r.header):lower() ~= AR then
    table.insert(gaps, string.format(
      'authentication-results has header = %s, so inbound Authentication-Results fields are kept', tostring(r.header)))
  end
  -- An attacker sends two forged fields; a later routine that resets the
  -- removal to "the first one" leaves the second standing.
  for _, later in ipairs(later_removals(opts, use, r.header or 'Authentication-Results')) do
    if later[2] ~= 0 then
      table.insert(gaps, string.format(
        '%s runs after authentication-results and resets the removal of inbound fields to %s, which keeps some;'
          .. ' drop that entry, set it to 0, or list %s before authentication-results in use',
        later[1], tostring(later[2]), later[1]))
    end
  end
  -- milter_headers skips both kinds of sender unless told otherwise. Behind
  -- a proxy or NAT every connection is local, so that one can mean all mail.
  if opts.skip_authenticated ~= false and not lists(opts.authenticated_headers, AR) then
    table.insert(gaps,
      'forged results from authenticated senders are kept; add authentication-results to authenticated_headers')
  end
  if opts.skip_local ~= false and not lists(opts.local_headers, AR) then
    table.insert(gaps,
      'forged results from local addresses are kept; add authentication-results to local_headers')
  end
  return gaps
end

return stripping
