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

-- Built-in routines that queue their remove setting for every message they
-- run on. x-spam-level and x-os-fingerprint queue theirs only for some
-- messages, and a name that is not a built-in routine never runs.
local ALWAYS_QUEUES = {
  ['x-spamd-result'] = true, ['x-rspamd-server'] = true, ['x-rspamd-queue-id'] = true,
  ['x-rspamd-action'] = true, ['spam-header'] = true, ['x-virus'] = true,
  ['x-spamd-bar'] = true, ['x-spam-status'] = true, ['stat-signature'] = true,
  ['remove-header'] = true,
}

-- The kinds of sender milter_headers can skip a routine for, each with its
-- skip option and the list that exempts a routine from it.
local SENDERS = {
  authenticated = { skip = 'skip_authenticated', list = 'authenticated_headers', who = 'authenticated senders' },
  ['local'] = { skip = 'skip_local', list = 'local_headers', who = 'local addresses' },
}

--- runs reports whether milter_headers runs a routine for a message whose
--- sender is of every kind in kinds. skip_all is left out: it is reported on
--- its own, and it skips no routine for a recipient in extended_headers_rcpt.
local function runs(opts, name, kinds)
  for _, kind in ipairs(kinds) do
    local s = SENDERS[kind]
    if opts[s.skip] ~= false and not lists(opts[s.list], name) then return false end
  end
  return true
end

--- queued returns what a routine asks to be removed under the header name,
--- as { name, value, always }, or nil when it queues nothing known under that
--- name. always is true only when the routine queues the value for every
--- message it runs on.
local function queued(opts, name, header)
  local routines = type(opts.routines) == 'table' and opts.routines or {}
  local r = type(routines[name]) == 'table' and routines[name] or {}
  -- A custom routine runs instead of the built-in one with the same name,
  -- and what it queues is decided by its code.
  local builtin = not (type(opts.custom) == 'table' and opts.custom[name] ~= nil)
  local listed = type(r.headers) == 'table' and r.headers[header] ~= nil
  if name == AR then
    -- A custom routine in its place is reported on its own.
    if not builtin then return nil end
    -- With remove_ar_from it queues only the fields whose host matches, and
    -- none when no field matches.
    if r.remove_ar_from ~= nil then return { name, 'remove_ar_from', false } end
    -- A false remove queues nothing.
    if r.remove == false then return nil end
    return { name, r.remove == nil and 0 or r.remove, true }
  elseif name == 'remove-headers' then
    if listed then return { name, r.headers[header], builtin } end
  elseif name == 'add-headers' then
    -- Queues its own remove setting, 0 unless changed, for each header it
    -- adds.
    if listed then return { name, r.remove == nil and 0 or r.remove, builtin } end
  elseif r.header == header and r.remove then
    -- Every other built-in routine removes its own header, which is this
    -- one only if it was renamed to it. A false remove queues nothing.
    return { name, r.remove, builtin and ALWAYS_QUEUES[name] == true }
  end
  return nil
end

--- final_removal returns the entry that decides what is removed under the
--- header name once every routine has run, for a sender of the given kinds,
--- or nil when nothing is queued under it. The entry's fourth field is true
--- when its routine runs after authentication-results.
---
--- milter_headers collects removals in one table keyed by header name, and
--- every routine writes into it in turn. The last to write wins, so a later
--- routine replaces the "remove every field" that authentication-results
--- queued, and one after that can put it back. A key spelled in another case
--- is a separate entry and replaces nothing, so only an exact match counts.
---
--- An entry that restores full removal counts only if it is certain to be
--- queued: an attacker picks the message, so a routine that queues 0 for
--- some messages only protects none of them. One that narrows the removal
--- counts whenever it can be queued.
local function final_removal(opts, use, header, kinds)
  local last, after = nil, false
  for _, name in ipairs(run_order(opts, use)) do
    if runs(opts, name, kinds) then
      local q = queued(opts, name, header)
      if q and (q[3] or q[2] ~= 0) then
        q[4] = after
        last = q
      end
    end
    if name == AR then after = true end
  end
  return last
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
  if r.header ~= nil and tostring(r.header):lower() ~= AR then
    table.insert(gaps, string.format(
      'authentication-results has header = %s, so inbound Authentication-Results fields are kept', tostring(r.header)))
  end
  -- What counts is the removal left standing after the last routine, not
  -- each one queued on the way. It is worked out once per kind of sender
  -- that still gets authentication-results, because a routine that puts full
  -- removal back helps only the senders it is not skipped for. A compromised
  -- account is an authenticated sender, so the narrowed removal it gets is
  -- the one that matters.
  local custom = type(opts.custom) == 'table' and opts.custom[AR] ~= nil
  -- everyone holds what was reported for all senders, anyone what was
  -- reported at all, so one gap is not repeated per kind of sender.
  local everyone, anyone = {}, {}
  for _, kinds in ipairs({ {}, { 'authenticated' }, { 'local' }, { 'authenticated', 'local' } }) do
    local last = runs(opts, AR, kinds) and final_removal(opts, use, r.header or 'Authentication-Results', kinds)
    local gap
    if not runs(opts, AR, kinds) or (last and last[2] == 0) then
      -- Skipped senders are reported below; 0 removes every field of that
      -- name.
      gap = nil
    elseif last and last[2] == 'remove_ar_from' then
      -- Its matcher reads only a plain name at the start of the field, so a
      -- forged "(c) mx.example; sworn=pass" or a quoted authserv-id gets
      -- through.
      gap = 'authentication-results has remove_ar_from set, which misses forged fields that start with a comment'
        .. ' or quotes'
    elseif last and last[4] then
      -- An attacker sends two forged fields; a later routine that resets the
      -- removal to "the first one" leaves the second standing.
      gap = string.format(
        '%s runs after authentication-results and resets the removal of inbound fields to %s, which keeps some;'
          .. ' drop that entry, set it to 0, or list %s before authentication-results in use',
        last[1], tostring(last[2]), last[1])
      if #kinds > 0 and not everyone[gap] then
        -- Not so for every sender, so a routine that sets the removal back
        -- to 0 runs for the rest and is skipped for this kind. A sender of
        -- both kinds is covered by the report for either.
        local who, where = {}, {}
        for _, kind in ipairs(kinds) do
          who[#who + 1] = SENDERS[kind].who
          where[#where + 1] = SENDERS[kind].list
        end
        local narrowed = gap
        -- The advice to list the restoring routine holds only if there is
        -- one: senders with nothing skipped end at 0.
        local rest = final_removal(opts, use, r.header or 'Authentication-Results', {})
        local advice = rest and rest[2] == 0
          and string.format('the routine that sets it back to 0 is skipped for them; list that routine in %s as well',
            table.concat(where, ' and '))
          or string.format('it is the last routine that runs for them; set it to 0, or drop it from %s',
            table.concat(where, ' and '))
        gap = not (#kinds > 1 and anyone[narrowed]) and string.format(
          '%s runs after authentication-results and resets the removal of inbound fields to %s for %s, which keeps'
            .. ' some: %s',
          last[1], tostring(last[2]), table.concat(who, ' on '), advice) or nil
        anyone[narrowed] = true
      end
    elseif not custom then
      -- authentication-results has the last word, or queued nothing and
      -- left an earlier routine's entry standing. A positive number removes
      -- only that one field, so a second forged field survives, and false
      -- removes none.
      gap = string.format(
        'authentication-results has remove = %s, which keeps some inbound fields; leave it at 0', tostring(r.remove))
    end
    if gap and not anyone[gap] then
      if #kinds == 0 then everyone[gap] = true end
      anyone[gap] = true
      table.insert(gaps, gap)
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
