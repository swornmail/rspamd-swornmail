local t = require 'harness'
local stripping = require 'sworn.stripping'

-- conf/milter_headers.conf, as rspamd hands it to a module.
local SHIPPED = {
  use = { 'authentication-results' },
  authenticated_headers = { 'authentication-results' },
  local_headers = { 'authentication-results' },
  routines = { ['authentication-results'] = { add_smtp_user = false } },
}

local function with(changes)
  local opts = {}
  for k, v in pairs(SHIPPED) do opts[k] = v end
  for k, v in pairs(changes) do opts[k] = v end
  return opts
end

local function routine(fields)
  return { ['authentication-results'] = fields }
end

local function has(gaps, needle)
  for _, g in ipairs(gaps) do
    if g:find(needle, 1, true) then return true end
  end
  return false
end

t.test('the shipped config leaves no forged result standing', function()
  t.eq(#stripping.gaps(SHIPPED), 0, 'gaps in the shipped config')
end)

-- Each case is a config under which a forged "mx.example; sworn=pass" from
-- the named sender survives into the mailbox, and the phrase the startup
-- warning must contain so the operator can find the setting.
t.test('reports every config that keeps forged results', function()
  local cases = {
    { 'milter_headers not configured', nil, 'not configured' },
    { 'milter_headers disabled', with({ enabled = false }), 'disabled' },
    { 'routine not in use', with({ use = { 'x-spamd-bar' } }), 'use' },
    { 'another routine named on its own', with({ use = 'x-spamd-bar' }), 'use' },
    -- An attacker sends two forged fields and the second one stays.
    { 'only the first field removed', with({ routines = routine({ remove = 1 }) }), 'remove' },
    { 'removal turned off', with({ routines = routine({ remove = false }) }), 'remove' },
    -- Matches a plain leading name only, so "(c) mx.example" and a quoted
    -- authserv-id get through.
    { 'removal narrowed by hostname', with({ routines = routine({ remove_ar_from = { 'mx.example' } }) }), 'remove_ar_from' },
    -- The routine then removes and writes a different field entirely.
    { 'routine writes another header', with({ routines = routine({ header = 'X-Auth-Results' }) }), 'header' },
    -- milter_headers checks this after the per-sender lists, so it turns the
    -- routine off for everyone.
    { 'every sender skipped', with({ skip_all = true }), 'skip_all' },
    -- milter_headers runs a custom routine instead of a built-in one with
    -- the same name.
    { 'custom routine shadows the built-in', with({ custom = { ['authentication-results'] = 'return function() end' } }), 'custom' },
    -- Routines share one removal table and the last to write wins, so each
    -- of these replaces "remove every field" with "remove the first": the
    -- attacker sends two forged fields and the second one stays.
    { 'remove-headers narrows it afterwards', with({
      use = { 'authentication-results', 'remove-headers' },
      routines = { ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } } },
    }), 'remove-headers runs after' },
    { 'remove-header narrows it afterwards', with({
      use = { 'authentication-results', 'remove-header' },
      routines = { ['remove-header'] = { header = 'Authentication-Results', remove = 2 } },
    }), 'remove-header runs after' },
    { 'add-headers narrows it afterwards', with({
      use = { 'authentication-results', 'add-headers' },
      routines = { ['add-headers'] = { headers = { ['Authentication-Results'] = 'x' }, remove = 1 } },
    }), 'add-headers runs after' },
    { 'a renamed routine narrows it afterwards', with({
      use = { 'authentication-results', 'x-spamd-bar' },
      routines = { ['x-spamd-bar'] = { header = 'Authentication-Results', remove = 1 } },
    }), 'x-spamd-bar runs after' },
    -- The key has to match the header name authentication-results was
    -- given, whatever that is.
    { 'narrowed under a renamed header', with({
      use = { 'authentication-results', 'remove-headers' },
      routines = {
        ['authentication-results'] = { header = 'authentication-results' },
        ['remove-headers'] = { headers = { ['authentication-results'] = 1 } },
      },
    }), 'remove-headers runs after' },
    -- The last routine to write decides, so setting the removal back to 0
    -- does not help when a narrowing routine runs after that.
    { 'restored, then narrowed again', with({
      use = { 'authentication-results', 'remove-header', 'remove-headers' },
      routines = {
        ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
      },
    }), 'remove-headers runs after' },
    -- milter_headers skips remove-header for an authenticated sender here
    -- and still runs the other two, so a compromised account sends two
    -- forged fields and the second one stays.
    { 'restored only for senders who are not authenticated', with({
      use = { 'authentication-results', 'remove-headers', 'remove-header' },
      authenticated_headers = { 'authentication-results', 'remove-headers' },
      local_headers = { 'authentication-results', 'remove-headers', 'remove-header' },
      routines = {
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
        ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
      },
    }), 'for authenticated senders' },
    { 'restored only for senders that are not local', with({
      use = { 'authentication-results', 'remove-headers', 'remove-header' },
      authenticated_headers = { 'authentication-results', 'remove-headers', 'remove-header' },
      local_headers = { 'authentication-results', 'remove-headers' },
      routines = {
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
        ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
      },
    }), 'for local addresses' },
    -- No routine restores full removal for anyone here, so the advice must
    -- not send the operator looking for one.
    { 'narrowed differently for authenticated senders', with({
      use = { 'authentication-results', 'remove-headers', 'remove-header' },
      authenticated_headers = { 'authentication-results', 'remove-headers' },
      local_headers = { 'authentication-results', 'remove-headers', 'remove-header' },
      routines = {
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
        ['remove-header'] = { header = 'Authentication-Results', remove = 2 },
      },
    }), 'it is the last routine that runs for them' },
    -- x-spam-level queues its removal only for a message scoring 1 or more,
    -- and the attacker's forged message need not.
    { 'restored only for some messages', with({
      use = { 'authentication-results', 'remove-headers', 'x-spam-level' },
      routines = {
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
        ['x-spam-level'] = { header = 'Authentication-Results', remove = 0 },
      },
    }), 'remove-headers runs after' },
    -- The custom routine runs instead of remove-header, and what it removes
    -- is not in the config.
    { 'restored by a routine a custom one replaces', with({
      use = { 'authentication-results', 'remove-headers', 'remove-header' },
      custom = { ['remove-header'] = 'return function() end' },
      routines = {
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
        ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
      },
    }), 'remove-headers runs after' },
    -- Nothing is queued by authentication-results, so the earlier entry
    -- stands.
    { 'removal turned off after an earlier routine narrowed it', with({
      use = { 'remove-headers', 'authentication-results' },
      routines = {
        ['authentication-results'] = { remove = false },
        ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
      },
    }), 'remove = false' },
    -- A compromised account can forge results for local recipients.
    { 'authenticated senders skipped', with({ authenticated_headers = {} }), 'authenticated_headers' },
    -- Behind a proxy or NAT every connection looks local, so this can cover
    -- all inbound mail.
    { 'local senders skipped', with({ local_headers = {} }), 'local_headers' },
  }
  for _, c in ipairs(cases) do
    local gaps = stripping.gaps(c[2])
    t.ok(#gaps > 0, c[1] .. ': no gap reported')
    t.ok(has(gaps, c[3]), c[1] .. ': no gap naming ' .. c[3])
  end
end)

t.test('accepts other ways of stripping for every sender', function()
  t.eq(#stripping.gaps({
    use = { 'authentication-results' },
    skip_authenticated = false, skip_local = false,
  }), 0, 'skip_* turned off instead of listing the routine')
  t.eq(#stripping.gaps(with({ routines = routine({ remove = 0 }) })), 0, 'explicit remove = 0')
  t.eq(#stripping.gaps(with({ routines = routine({ header = 'authentication-results' }) })), 0,
    'header name in another case')
  t.eq(#stripping.gaps(with({ use = { 'x-spamd-bar', 'authentication-results' } })), 0,
    'routine alongside others')
  -- A routine that runs first is overwritten by authentication-results.
  t.eq(#stripping.gaps(with({
    use = { 'remove-headers', 'authentication-results' },
    routines = { ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } } },
  })), 0, 'remove-headers listed before the routine')
  t.eq(#stripping.gaps(with({
    use = { 'authentication-results', 'remove-headers' },
    routines = { ['remove-headers'] = { headers = { ['Authentication-Results'] = 0, ['X-Old'] = 1 } } },
  })), 0, 'a later routine that also removes every field')
  -- The last routine to write decides: rspamd is sent "remove every field",
  -- so the narrowed entry in between never reaches the MTA.
  t.eq(#stripping.gaps(with({
    use = { 'authentication-results', 'remove-headers', 'remove-header' },
    authenticated_headers = { 'authentication-results', 'remove-headers', 'remove-header' },
    local_headers = { 'authentication-results', 'remove-headers', 'remove-header' },
    routines = {
      ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
      ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
    },
  })), 0, 'narrowed, then set back to every field')
  -- The same with no routine skipped for anyone.
  t.eq(#stripping.gaps({
    use = { 'authentication-results', 'remove-headers', 'remove-header' },
    skip_authenticated = false, skip_local = false,
    routines = {
      ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
      ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
    },
  }), 0, 'narrowed, then set back, with no sender skipped')
  -- The narrowing routine is skipped for the same senders as the one that
  -- sets it back, so neither kind is left with the narrowed entry.
  t.eq(#stripping.gaps(with({
    use = { 'authentication-results', 'remove-headers', 'remove-header' },
    routines = {
      ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } },
      ['remove-header'] = { header = 'Authentication-Results', remove = 0 },
    },
  })), 0, 'narrowed and set back by routines skipped for the same senders')
  t.eq(#stripping.gaps(with({
    use = { 'authentication-results', 'remove-headers' },
    authenticated_headers = { 'authentication-results', 'remove-headers' },
    local_headers = { 'authentication-results', 'remove-headers' },
    routines = {
      ['authentication-results'] = { remove = 1 },
      ['remove-headers'] = { headers = { ['Authentication-Results'] = 0 } },
    },
  })), 0, 'the routine\'s own narrowed removal set back by a later one')
  -- Another spelling is a separate entry in the removal table, so the
  -- "remove every field" entry is still sent; checked against 4.2.2.
  t.eq(#stripping.gaps(with({
    use = { 'authentication-results', 'remove-headers' },
    routines = { ['remove-headers'] = { headers = { ['authentication-results'] = 1 } } },
  })), 0, 'a later routine keyed in another case')
  t.eq(#stripping.gaps(with({
    use = { 'authentication-results', 'add-headers' },
    routines = { ['add-headers'] = { headers = { ['X-Note'] = 'x' }, remove = 1 } },
  })), 0, 'a later routine touching other headers')
  -- Configured but not in use, so it never runs.
  t.eq(#stripping.gaps(with({
    routines = { ['remove-headers'] = { headers = { ['Authentication-Results'] = 1 } } },
  })), 0, 'a narrowing routine that is not in use')
  -- milter_headers turns a single name into a list; checked against 4.2.2.
  t.eq(#stripping.gaps(with({ use = 'authentication-results' })), 0, 'routine named on its own')
end)

os.exit(t.report('sworn.stripping'))
