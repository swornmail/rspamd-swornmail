--[[
SwornMail Mode-1 attestation for rspamd.

Runs DNS-only discovery for the connecting IPv6 address and reports the result
as a symbol and an Authentication-Results entry. Informational by default:
every symbol scores 0.0, so installing this module cannot change any verdict
until an operator deliberately gives the symbols weight.

Fail-open by construction. Absence of attestation, DNS failure, and every
error path leave message handling exactly as it was — SwornMail never rejects
mail on its own, and a failed check never counts against a sender.

Install: see README.md. Protocol: github.com/swornmail/spec.
]]

if confighelp then return end

local rspamd_dns = require 'rspamd_dns'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local lua_util = require 'lua_util'

local N = 'swornmail'

local settings = {
  enabled = true,
  symbol_pass = 'SWORN_PASS',
  symbol_testing = 'SWORN_TESTING',
  symbol_none = 'SWORN_NONE',
  symbol_temperror = 'SWORN_TEMPERROR',
  -- Where the sworn.* protocol library was installed. Prepended to
  -- package.path so the module can be split into testable parts.
  lib_path = '/etc/rspamd/lua',
  -- Name written into Authentication-Results. Defaults to this host's name,
  -- which is what an ADMD border MTA stamps and what the trust-boundary
  -- stripping rule keys on. Set it explicitly when rspamd's hostname is not
  -- the ADMD's public identity.
  authserv_id = nil,
  -- Where the rendered AR value is left for the milter_headers routine.
  mempool_variable = 'sworn_ar',
  -- Trust the MTA's rDNS name when it supplies one. Under a Postfix milter a
  -- non-nil hostname has already been forward-confirmed, so accepting it
  -- saves two queries. Set false to always confirm here instead.
  use_mta_hostname = true,
}

local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

if not settings.enabled then
  lua_util.disable_module(N, 'config')
  return
end

package.path = settings.lib_path .. '/?.lua;' .. package.path
local ok_lib, discovery = pcall(require, 'sworn.discovery')
local ok_ar, authres = pcall(require, 'sworn.authres')
if not ok_lib or not ok_ar then
  -- A half-installed module must not take rspamd down with it.
  lua_util.disable_module(N, 'config')
  rspamd_logger.errx(rspamd_config,
    'swornmail: cannot load the sworn library from %s — check lib_path (%s)',
    settings.lib_path, discovery)
  return
end

-- Error strings librdns reports for a definite negative answer. Anything else
-- is a temporary failure and must not be reported as "no attestation":
-- treating a resolver outage as a negative answer would let an attacker
-- suppress attestation by disrupting DNS.
local DEFINITE_NEGATIVE = {
  ['no records with this name'] = true,
  ['requested record is not found'] = true,
}

--- make_resolver adapts rspamd's coroutine DNS API to the contract the
--- discovery module expects: results, or nil plus a temporary-error string,
--- or nil, nil for a definite negative.
local function make_resolver(task)
  local function query(kind, name)
    local ok, results = rspamd_dns.request({ task = task, type = kind, name = name })
    lua_util.debugm(N, task, 'dns %s %s -> ok=%s first=%s', kind, name, tostring(ok),
      type(results) == 'table' and tostring(results[1]) or tostring(results))
    if ok then return results, nil end
    -- A nil first return means the request could not be scheduled at all
    -- (per-task DNS cap) — a resource limit, so temporary.
    if ok == nil then return nil, 'request not scheduled' end
    if type(results) == 'string' and DEFINITE_NEGATIVE[results] then return nil, nil end
    return nil, results or 'dns error'
  end

  return {
    txt = function(name) return query('txt', name) end,
    ptr = function(addr) return query('ptr', addr) end,
    aaaa = function(host) return query('aaaa', host) end,
  }
end

--- verified_hostname returns the MTA-supplied rDNS name when it can be
--- trusted. Postfix reports nothing usable when forward confirmation failed,
--- so a plain name here has already passed FCrDNS; anything else and
--- discovery confirms it itself.
local function verified_hostname(task)
  if not settings.use_mta_hostname then return nil end
  local host = task:get_hostname()
  if not host or host == '' or host:sub(1, 1) == '[' then return nil end
  return host
end

local function check_sworn(task)
  local from_ip = task:get_from_ip()
  if not from_ip or not from_ip:is_valid() then return end
  -- Mode 1 attests IPv6 space; IPv4 senders are out of scope, not a failure.
  if from_ip:get_version() ~= 6 then return end

  local res = discovery.run(make_resolver(task), tostring(from_ip), {
    verified_hostname = verified_hostname(task),
  })

  local symbol = settings['symbol_' .. authres.kind(res)]
  local option
  if res.outcome == 'pass' then
    option = string.format('%s:%s', res.operator, res.unit)
  end
  task:insert_result(symbol, 1.0, option)

  -- Hand the rendered value to the milter_headers custom routine: rspamd's
  -- own Authentication-Results generator has a fixed method list and no way
  -- to register another, so the sworn= result travels as a second AR field,
  -- which RFC 8601 section 4 explicitly permits.
  task:get_mempool():set_variable(settings.mempool_variable, authres.render(settings.authserv_id, res))

  lua_util.debugm(N, task, 'sworn=%s operator=%s queries=%s',
    res.outcome, res.operator or '-', res.queries)
end

if not settings.authserv_id then
  settings.authserv_id = rspamd_util.get_hostname() or 'localhost'
end

local id = rspamd_config:register_symbol({
  name = 'SWORN_CHECK',
  type = 'callback',
  -- The discovery walk yields on DNS, so the callback runs on a coroutine.
  flags = 'coro,empty,nostat',
  callback = check_sworn,
  augmentations = { lua_util.dns_timeout_augmentation(rspamd_config) },
})

-- Every symbol is informational: score 0.0 means installing this module
-- changes no verdict until an operator opts in by assigning weight.
for _, name in ipairs({
  settings.symbol_pass, settings.symbol_testing,
  settings.symbol_none, settings.symbol_temperror,
}) do
  rspamd_config:register_symbol({
    name = name,
    parent = id,
    type = 'virtual',
    flags = 'empty,nostat',
    score = 0.0,
    group = N,
  })
end

rspamd_logger.infox(rspamd_config, 'swornmail: Mode-1 attestation enabled, authserv-id %s', settings.authserv_id)
