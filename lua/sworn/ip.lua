--[[
IPv6 address and prefix arithmetic for SwornMail, in dependency-free Lua.

Deliberately does not use rspamd_ip. This is a third implementation of rules
the Go and Rust verifiers already enforce, so it is kept runnable outside
rspamd in order to be driven by the cross-implementation differential
harness. Divergence here is a conformance bug, not a local style choice.

Addresses are 16-element arrays of byte values, 1-indexed. Record text is
attacker-supplied, so parsing is strict and returns nil rather than guessing.
]]

local ip = {}

-- Global unicast 2000::/3: the range every attested prefix must fall within.
local GLOBAL_UNICAST_FIRST, GLOBAL_UNICAST_LAST = 0x20, 0x3f

ip.MIN_PREFIX_LEN = 32
ip.MAX_PREFIX_LEN = 64

--- OBSERVED_UNIT_LEN is the fallback reputation boundary: the connecting
--- source's /64. It is its own constant rather than derived from a record's
--- declared unit on purpose — a publisher-declared unit must not be able to
--- widen where reputation lands, so a future change to the unit range cannot
--- silently move this boundary.
ip.OBSERVED_UNIT_LEN = 64

--- split_groups parses a colon-separated run into 16-bit groups. A trailing
--- dotted quad (the ::ffff:a.b.c.d form) expands into two groups.
local function split_groups(s)
  local out = {}
  if s == '' then return out end
  local pos = 1
  while true do
    local nxt = s:find(':', pos, true)
    local part = nxt and s:sub(pos, nxt - 1) or s:sub(pos)
    if part == '' then return nil end
    if part:find('.', 1, true) then
      if nxt then return nil end -- a dotted quad may only be last
      local a, b, c, d = part:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
      if not a then return nil end
      local quad = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
      for i, v in ipairs(quad) do
        if v > 255 then return nil end
        local text = ({ a, b, c, d })[i]
        if #text > 1 and text:sub(1, 1) == '0' then return nil end -- no leading zeros
      end
      out[#out + 1] = quad[1] * 256 + quad[2]
      out[#out + 1] = quad[3] * 256 + quad[4]
    else
      if #part > 4 or part:find('[^0-9A-Fa-f]') then return nil end
      out[#out + 1] = tonumber(part, 16)
    end
    if not nxt then break end
    pos = nxt + 1
  end
  return out
end

local function groups_to_bytes(groups)
  local bytes = {}
  for i = 1, 8 do
    bytes[i * 2 - 1] = math.floor(groups[i] / 256)
    bytes[i * 2] = groups[i] % 256
  end
  return bytes
end

--- parse converts IPv6 text to 16 bytes, or nil if malformed.
function ip.parse(s)
  if type(s) ~= 'string' or #s == 0 or #s > 45 then return nil end
  if s:find('[^0-9A-Fa-f:%.]') then return nil end

  local dbl = s:find('::', 1, true)
  local groups
  if dbl then
    if s:find('::', dbl + 1, true) then return nil end -- at most one '::'
    local left = split_groups(s:sub(1, dbl - 1))
    local right = split_groups(s:sub(dbl + 2))
    if not left or not right then return nil end
    -- '::' must stand for at least one zero group.
    if #left + #right > 7 then return nil end
    groups = {}
    for _, g in ipairs(left) do groups[#groups + 1] = g end
    for _ = 1, 8 - #left - #right do groups[#groups + 1] = 0 end
    for _, g in ipairs(right) do groups[#groups + 1] = g end
  else
    groups = split_groups(s)
    if not groups or #groups ~= 8 then return nil end
  end
  return groups_to_bytes(groups)
end

--- masked returns a copy of bytes with every bit beyond `bits` cleared.
function ip.masked(bytes, bits)
  local out = {}
  for i = 1, 16 do
    local before = (i - 1) * 8
    if bits >= before + 8 then
      out[i] = bytes[i]
    elseif bits <= before then
      out[i] = 0
    else
      local drop = 2 ^ (8 - (bits - before))
      out[i] = bytes[i] - (bytes[i] % drop)
    end
  end
  return out
end

function ip.equal(a, b)
  for i = 1, 16 do
    if a[i] ~= b[i] then return false end
  end
  return true
end

--- contains reports whether addr falls inside prefix/bits.
function ip.contains(prefix, bits, addr)
  return ip.equal(ip.masked(prefix, bits), ip.masked(addr, bits))
end

function ip.is_global_unicast(addr)
  return addr[1] >= GLOBAL_UNICAST_FIRST and addr[1] <= GLOBAL_UNICAST_LAST
end

-- Transition ranges: Teredo 2001::/32 and 6to4 2002::/16. An attested prefix
-- must not overlap them, and a source inside them is never matched.
local function in_teredo(a) return a[1] == 0x20 and a[2] == 0x01 and a[3] == 0 and a[4] == 0 end
local function in_6to4(a) return a[1] == 0x20 and a[2] == 0x02 end

--- eligible_source reports whether a connecting address may be matched
--- against an attested prefix at all: ordinary global unicast only. The
--- 2000::/3 gate also excludes IPv4-mapped, IPv4-compatible, NAT64,
--- link-local, ULA, and multicast sources, closing the cross-family
--- confusion where one IPv4 address maps deterministically into IPv6.
function ip.eligible_source(addr)
  if not ip.is_global_unicast(addr) then return false end
  return not (in_teredo(addr) or in_6to4(addr))
end

--- valid_prefix enforces the canonical-form and range rules a published
--- prefix must satisfy: masked, length 32..64, inside 2000::/3, clear of the
--- transition ranges. A prefix at least 32 bits long that starts inside
--- Teredo or 6to4 lies wholly within it, so a first-address test suffices.
function ip.valid_prefix(addr, bits)
  if type(bits) ~= 'number' or bits % 1 ~= 0 then return false end
  if bits < ip.MIN_PREFIX_LEN or bits > ip.MAX_PREFIX_LEN then return false end
  if not ip.equal(addr, ip.masked(addr, bits)) then return false end
  if not ip.is_global_unicast(addr) then return false end
  return not (in_teredo(addr) or in_6to4(addr))
end

--- format renders 16 bytes as RFC 5952 canonical text, matching what the Go
--- and Rust implementations emit so reported units compare equal.
function ip.format(bytes)
  local groups = {}
  for i = 1, 8 do
    groups[i] = bytes[i * 2 - 1] * 256 + bytes[i * 2]
  end
  -- Longest run of two or more zero groups, leftmost on a tie, becomes '::'.
  local best_start, best_len, cur_start, cur_len = 0, 0, 0, 0
  for i = 1, 8 do
    if groups[i] == 0 then
      if cur_len == 0 then cur_start = i end
      cur_len = cur_len + 1
      if cur_len > best_len then best_start, best_len = cur_start, cur_len end
    else
      cur_len = 0
    end
  end

  local head, tail = {}, {}
  if best_len >= 2 then
    for i = 1, best_start - 1 do head[#head + 1] = string.format('%x', groups[i]) end
    for i = best_start + best_len, 8 do tail[#tail + 1] = string.format('%x', groups[i]) end
    return table.concat(head, ':') .. '::' .. table.concat(tail, ':')
  end
  for i = 1, 8 do head[#head + 1] = string.format('%x', groups[i]) end
  return table.concat(head, ':')
end

function ip.format_prefix(bytes, bits)
  return ip.format(bytes) .. '/' .. tostring(bits)
end

--- parse_prefix splits and validates "<addr>/<bits>" from a policy record.
--- Returns bytes, bits or nil.
function ip.parse_prefix(s)
  if type(s) ~= 'string' then return nil end
  local addr_text, bits_text = s:match('^([^/]+)/(%d+)$')
  if not addr_text then return nil end
  if #bits_text > 3 or (#bits_text > 1 and bits_text:sub(1, 1) == '0') then return nil end
  local addr = ip.parse(addr_text)
  if not addr then return nil end
  local bits = tonumber(bits_text)
  if bits > 128 then return nil end
  return addr, bits
end

--- reverse_name builds the reverse-tree query name for the enclosing prefix
--- of `bits` length, `_sworn` leftmost so the name falls inside the
--- operator's own reverse delegation. Discovery asks at /64 and /48 only.
function ip.reverse_name(addr, bits)
  if bits % 4 ~= 0 or bits < 4 or bits > 128 then return nil end
  local nibbles = {}
  for i = 1, 16 do
    nibbles[#nibbles + 1] = string.format('%x', math.floor(addr[i] / 16))
    nibbles[#nibbles + 1] = string.format('%x', addr[i] % 16)
  end
  local parts = { '_sworn' }
  for i = bits / 4, 1, -1 do
    parts[#parts + 1] = nibbles[i]
  end
  return table.concat(parts, '.') .. '.ip6.arpa'
end

return ip
