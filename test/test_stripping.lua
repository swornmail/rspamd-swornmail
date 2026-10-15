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
  -- milter_headers turns a single name into a list; checked against 4.2.2.
  t.eq(#stripping.gaps(with({ use = 'authentication-results' })), 0, 'routine named on its own')
end)

os.exit(t.report('sworn.stripping'))
