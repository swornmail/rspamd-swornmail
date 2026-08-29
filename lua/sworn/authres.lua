--[[
Authentication-Results rendering for Mode-1 outcomes.

Byte-for-byte the same vocabulary as the Go reference's discover.AuthResults;
the differential harness compares this output against it. Kept free of rspamd
calls so it can be driven directly by tests and by the harness.
]]

local authres = {}

--- render formats a discovery result as an Authentication-Results value.
---
--- A confirmed operator publishing t=y is reported as none carrying
--- policy.wouldbe, never as pass: pass asserts an accountability the operator
--- has explicitly not accepted, and consumers keying on sworn=pass would read
--- a trial deployment as a committed one.
function authres.render(authserv_id, res)
  local outcome = res and res.outcome or 'none'
  if outcome == 'pass' and res.testing then
    return authserv_id .. '; sworn=none policy.testing=y policy.wouldbe=pass ' .. authres.properties(res)
  elseif outcome == 'pass' then
    return authserv_id .. '; sworn=pass ' .. authres.properties(res)
  elseif outcome == 'temperror' then
    return authserv_id .. '; sworn=temperror'
  end
  return authserv_id .. '; sworn=none'
end

--- properties renders the diagnostic properties shared by pass and testing
--- results. Prefixes are quoted: they contain ':' and '/', which RFC 8601
--- requires be emitted as a quoted-string.
---
--- Both units are emitted because they mean different things and a consumer
--- reading only the header has no other way to tell them apart. policy.unit is
--- the aggregation the operator asked for. policy.observed is the source /64
--- this connection actually corroborated, and is what reputation attaches to
--- unless the receiver holds independent evidence of wider control.
function authres.properties(res)
  return string.format('policy.mode=%s policy.op=%s policy.unit=%q policy.observed=%q',
    res.mode, res.operator, res.unit, res.observed)
end

--- kind classifies an outcome for symbol selection. Testing is its own kind
--- so an operator can see trial traffic distinctly, and so it can never be
--- counted as a pass.
function authres.kind(res)
  local outcome = res and res.outcome or 'none'
  if outcome == 'pass' then
    return res.testing and 'testing' or 'pass'
  elseif outcome == 'temperror' then
    return 'temperror'
  end
  return 'none'
end

return authres
