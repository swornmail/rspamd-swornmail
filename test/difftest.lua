--[[
Differential arm: answers the same questions as swornmail-go's recorddiff
using this implementation, so any disagreement between the two is visible.

Reads cases on stdin, writes "<name>\t<verdict>" per line:
  policy\t<name>\t<hex record>\t<source>  -> err | nomatch | match:<unit prefix>
  elig\t<name>\t<source>                  -> yes | no
]]

local ip = require 'sworn.ip'
local record = require 'sworn.record'

local function unhex(s)
  return (s:gsub('%x%x', function(byte) return string.char(tonumber(byte, 16)) end))
end

--- policy_verdict mirrors what a receiver decides from one policy record and
--- one connecting address: reject the record, find no covering prefix, or
--- derive the reputation unit from the longest match.
local function policy_verdict(text, source)
  local policy = record.parse_policy(text)
  if not policy then return 'err' end
  local addr = ip.parse(source)
  if not addr then return 'nomatch' end
  local best
  for _, p in ipairs(policy.prefixes) do
    if ip.contains(p.addr, p.bits, addr) and (not best or p.bits > best.bits) then
      best = p
    end
  end
  if not best then return 'nomatch' end
  return 'match:' .. ip.format_prefix(ip.masked(addr, policy.unit), policy.unit)
end

local function elig_verdict(source)
  local addr = ip.parse(source)
  if not addr then return 'no' end
  return ip.eligible_source(addr) and 'yes' or 'no'
end

for line in io.lines() do
  local kind, rest = line:match('^([^\t]*)\t(.*)$')
  if kind == 'policy' then
    local name, hex, source = rest:match('^([^\t]*)\t([^\t]*)\t(.*)$')
    if name then
      io.write(name, '\t', policy_verdict(unhex(hex), source), '\n')
    end
  elseif kind == 'elig' then
    local name, source = rest:match('^([^\t]*)\t(.*)$')
    if name then
      io.write(name, '\t', elig_verdict(source), '\n')
    end
  end
end
