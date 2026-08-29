--[[
SwornMail DNS record parsing: the policy record and the reverse-tree pointer.

Mirrors the tag rules the Go and Rust implementations enforce — v= first, no
duplicate tag, no whitespace inside a value, unknown tags ignored for forward
compatibility. Anything malformed yields no record rather than a partial one:
a receiver that guesses at a broken record is a receiver that can be steered.
]]

local ip = require 'sworn.ip'

local record = {}

record.VERSION = 'SWORN1'
record.MAX_PREFIXES = 64
record.DEFAULT_UNIT = 64

--- split_tags returns an ordered array of {key, value} pairs, or nil if the
--- shared tag syntax is violated.
local function split_tags(txt)
  if type(txt) ~= 'string' then return nil end
  -- A SwornMail record is printable ASCII by construction: domains are LDH,
  -- prefixes and units are digits and punctuation, rua is a dot-atom. So the
  -- rule is the simplest one three implementations can agree on exactly --
  -- reject every byte outside 0x20..0x7E, plus HTAB.
  --
  -- 'Whitespace' is where parsers silently disagree: Go's unicode.IsSpace
  -- covers U+00A0 and U+3000, this module's %s is byte-wise, and Rust's
  -- is_ascii_whitespace excludes VT. The same record then parses differently
  -- in three places. Restricting the record to an explicit octet set removes
  -- the disagreement at its source, and takes CR, LF, NUL, DEL and every
  -- other C0 control with it.
  --
  -- HTAB is admitted because a hand-edited zone file legitimately contains one
  -- between tags, and all three implementations already strip it there and
  -- reject it inside a value.
  if txt:find('[^\9\32-\126]') then return nil end
  local pairs_out, seen, index = {}, {}, 0
  for part in (txt .. ';'):gmatch('([^;]*);') do
    part = part:match('^%s*(.-)%s*$')
    if part ~= '' then
      index = index + 1
      local k, v = part:match('^([^=]*)=(.*)$')
      if not k then return nil end
      k = k:match('^%s*(.-)%s*$')
      v = v:match('^%s*(.-)%s*$')
      if index == 1 and k ~= 'v' then return nil end
      -- Only SP and HTAB survive the octet gate above, and those are
      -- exactly what 'whitespace' means here.
      if v:find('[ \t]') then return nil end
      if seen[k] then return nil end -- a duplicate tag makes the record malformed
      seen[k] = true
      pairs_out[#pairs_out + 1] = { k, v }
    end
  end
  return pairs_out
end
record.split_tags = split_tags

local function valid_rua(value)
  local address = value:match('^mailto:(.+)$')
  if not address then return false end
  local localpart, domain = address:match('^([^@]+)@([^@]+)$')
  if not localpart or not record.valid_domain(domain) then return false end
  for atom in (localpart .. '.'):gmatch('([^%.]*)%.') do
    if atom == '' or atom:find("[^A-Za-z0-9!#$%%&'*+/%=?^_`{|}~%-]") then
      return false
    end
  end
  return true
end

--- valid_domain enforces the operator-domain syntax: A-label form, <= 253
--- octets, each label 1..63 LDH not starting or ending with '-'. This rejects
--- empty labels, wildcards, and CR/LF before any value reaches a resolver or
--- a header — an unchecked domain here is header-injection material.
function record.valid_domain(s)
  if type(s) ~= 'string' or #s < 1 or #s > 253 then return false end
  for label in (s .. '.'):gmatch('([^%.]*)%.') do
    if #label < 1 or #label > 63 then return false end
    if label:find('[^%w%-]') then return false end
    if label:sub(1, 1) == '-' or label:sub(-1) == '-' then return false end
  end
  return true
end

--- parse_policy reads a _prefixes._sworn record. Returns a table with
--- prefixes (array of {addr, bits}), unit, testing, rua — or nil.
function record.parse_policy(txt)
  local tags = split_tags(txt)
  if not tags then return nil end
  local out = { prefixes = {}, unit = record.DEFAULT_UNIT, testing = false, rua = nil }
  local have_version = false
  for _, kv in ipairs(tags) do
    local k, v = kv[1], kv[2]
    if k == 'v' then
      if v ~= record.VERSION then return nil end
      have_version = true
    elseif k == 'p' then
      for item in (v .. ','):gmatch('([^,]*),') do
        if item ~= '' then
          if #out.prefixes < record.MAX_PREFIXES then
            local addr, bits = ip.parse_prefix(item)
            -- An out-of-range or non-canonical prefix makes the whole record
            -- malformed: the operator sees the error instead of silently
            -- attesting something narrower than they wrote.
            if not addr or not ip.valid_prefix(addr, bits) then return nil end
            out.prefixes[#out.prefixes + 1] = { addr = addr, bits = bits }
          end
          -- Prefixes beyond the 64th are ignored, per the record limit.
        end
      end
    elseif k == 'u' then
      -- A leading '+' is accepted because both reference implementations
      -- accept it — Go's strconv.Atoi and Rust's integer FromStr each allow a
      -- sign — and a third implementation that is stricter than the two it
      -- must agree with produces divergence, not correctness. The draft has
      -- no ABNF for this field yet; when it gains one, all three tighten
      -- together through the vector process.
      if not v:match('^%+?%d+$') then return nil end
      -- GopherLua's tonumber does not accept a leading '+', although Go and
      -- Rust integer parsers do. Strip only the sign already admitted by the
      -- grammar above, and guard nil for numeric strings too large to parse.
      local numeric = v:sub(1, 1) == '+' and v:sub(2) or v
      local n = tonumber(numeric)
      if not n or n < 1 or n > ip.MAX_PREFIX_LEN then return nil end
      out.unit = n
    elseif k == 't' then
      for flag in (v .. ':'):gmatch('([^:]*):') do
        if flag == 'y' then out.testing = true end
        -- Unknown flags are ignored.
      end
    elseif k == 'rua' then
      -- Only the mailto: scheme is defined. rua is where a receiver would
      -- send aggregate reports, so an unexpected scheme is rejected here
      -- rather than handed onward as a destination.
      if not valid_rua(v) then return nil end
      out.rua = v
    end
    -- Unknown tags are ignored.
  end
  if not have_version then return nil end
  for _, prefix in ipairs(out.prefixes) do
    if out.unit < prefix.bits then return nil end
  end
  return out
end

--- parse_pointer reads a reverse-tree pointer record and returns the operator
--- domain it names. The domain is still subject to confirmation by the caller.
function record.parse_pointer(txt)
  local tags = split_tags(txt)
  if not tags then return nil end
  local have_version, domain = false, nil
  for _, kv in ipairs(tags) do
    if kv[1] == 'v' then
      if kv[2] ~= record.VERSION then return nil end
      have_version = true
    elseif kv[1] == 'd' then
      domain = kv[2]
    end
  end
  if not have_version or not domain or not record.valid_domain(domain) then return nil end
  return domain:lower()
end

--- select_sworn returns the single v=SWORN1 record from a TXT RRset. Zero or
--- more than one is not a usable record: with two present a verifier that
--- picked one arbitrarily could be steered by whichever the resolver happened
--- to order first.
function record.select_sworn(txts)
  if type(txts) ~= 'table' then return nil end
  local found, n = nil, 0
  local prefix = 'v=' .. record.VERSION
  for _, t in ipairs(txts) do
    if type(t) == 'string' and t:sub(1, #prefix) == prefix then
      found = t
      n = n + 1
    end
  end
  if n ~= 1 then return nil end
  return found
end

return record
