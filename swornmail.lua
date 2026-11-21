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
local lua_mime = require 'lua_mime'

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
  -- Take the client hostname the scan request carries as already
  -- forward-confirmed, saving two queries. Off by default: whoever sends the
  -- request chooses that name, and rspamd does not check it. Turn it on only
  -- when every scan client is an MTA that reports nothing but
  -- forward-confirmed names, as Postfix is documented to.
  use_mta_hostname = false,
  -- IPv6 prefixes never matched to an operator: your NAT64 or SIIT
  -- translation prefixes, and any of your own relays that carry outside
  -- traffic. Every translated client appears inside such a prefix, so a
  -- record covering it would otherwise vouch for all of them.
  ineligible_prefixes = {},
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
local ok_strip, stripping = pcall(require, 'sworn.stripping')
local ok_reply, dnsreply = pcall(require, 'sworn.dnsreply')
if not ok_lib or not ok_ar or not ok_strip or not ok_reply then
  -- A half-installed module must not take rspamd down with it.
  lua_util.disable_module(N, 'config')
  rspamd_logger.errx(rspamd_config,
    'swornmail: cannot load the sworn library from %s — check lib_path (%s)',
    settings.lib_path,
    not ok_lib and discovery or not ok_ar and authres or not ok_strip and stripping or dnsreply)
  return
end

-- A bad prefix disables the module rather than running without the list the
-- operator meant to give: results stop, which is never worse than none.
local ineligible, ineligible_err = discovery.parse_ineligible(settings.ineligible_prefixes)
if not ineligible then
  lua_util.disable_module(N, 'config')
  rspamd_logger.errx(rspamd_config, 'swornmail: ineligible_prefixes: %s', ineligible_err)
  return
end

--- make_resolver adapts rspamd's coroutine DNS API to the contract the
--- discovery module expects: results, or nil plus a temporary-error string,
--- or nil, nil for a definite negative. sworn.dnsreply decides which.
---
--- rspamd hands TXT data over as a C string, so a record with a NUL octet in
--- it arrives cut off at that octet and the rest is never seen here. The
--- parser rejects every other octet outside printable ASCII, but this one it
--- cannot: see "Limitations" in the README.
local function make_resolver(task)
  local function query(kind, name)
    local ok, results = rspamd_dns.request({ task = task, type = kind, name = name })
    lua_util.debugm(N, task, 'dns %s %s -> ok=%s first=%s', kind, name, tostring(ok),
      type(results) == 'table' and tostring(results[1]) or tostring(results))
    return dnsreply.read(kind, ok, results)
  end

  return {
    txt = function(name) return query('txt', name) end,
    ptr = function(addr) return query('ptr', addr) end,
    aaaa = function(host) return query('aaaa', host) end,
  }
end

--- verified_hostname returns the client hostname the scan request carried,
--- when the operator has said its scan clients can be trusted for it.
--- Postfix reports "unknown" or a bracketed address when forward confirmation
--- failed, so a plain name from it has already passed FCrDNS; anything else
--- and discovery confirms it itself.
---
--- The request header is read on purpose, not task:get_hostname(). When the
--- MTA supplies no usable name, a stock rspamd rule fills that slot from a
--- PTR lookup of its own that it never forward-confirms, and other plugins
--- write header-derived names there. Taking that as verified would let a
--- host name itself into an operator's domain exactly when its MTA had
--- refused to vouch for it.
local function verified_hostname(task)
  if not settings.use_mta_hostname then return nil end
  local hdr = task:get_request_header('Hostname')
  local host = hdr and tostring(hdr) or ''
  if host == '' or host:sub(1, 1) == '[' or host:lower() == 'unknown' then return nil end
  return host
end

local function check_sworn(task)
  local from_ip = task:get_from_ip()
  if not from_ip or not from_ip:is_valid() then return end
  -- Mode 1 attests IPv6 space; IPv4 senders are out of scope, not a failure.
  if from_ip:get_version() ~= 6 then return end

  local res = discovery.run(make_resolver(task), tostring(from_ip), {
    verified_hostname = verified_hostname(task),
    ineligible = ineligible,
  })

  local symbol = settings['symbol_' .. authres.kind(res)]
  task:insert_result(symbol, 1.0, (table.unpack or unpack)(authres.symbol_options(res)))

  -- rspamd's own Authentication-Results generator has a fixed method list,
  -- so the sworn= result goes out as a second field, which RFC 8601 section 4
  -- permits. It is added here rather than from a milter_headers custom
  -- routine: milter_headers lets a custom routine's output replace whatever
  -- its built-in routine queued under the same header name, which dropped
  -- rspamd's SPF, DKIM and DMARC results. Local and authenticated senders are
  -- skipped, as milter_headers does by default: that mail isn't arriving
  -- from another ADMD.
  if not task:get_user() and not from_ip:is_local() then
    lua_mime.modify_headers(task, {
      add = {
        ['Authentication-Results'] = { order = 1, value = authres.render(settings.authserv_id, res) },
      },
    })
  end

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

-- Removing forged inbound results is milter_headers' job, and rspamd's stock
-- config doesn't do it. That can't be fixed from here, but it shouldn't go
-- unnoticed.
for _, gap in ipairs(stripping.gaps(rspamd_config:get_all_opt('milter_headers'))) do
  rspamd_logger.warnx(rspamd_config, 'swornmail: forged sworn= results can reach mailboxes: %s', gap)
end
