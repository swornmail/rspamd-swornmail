--[[
Minimal test harness: no dependencies, so the suite runs under any stock Lua
or LuaJIT, including the one inside an rspamd container.
]]

local harness = { failures = 0, checks = 0, current = '?' }

function harness.test(name, fn)
  harness.current = name
  local ok, err = pcall(fn)
  if not ok then
    harness.failures = harness.failures + 1
    io.write(string.format('FAIL %s: %s\n', name, tostring(err)))
  end
end

local function fail(msg)
  harness.failures = harness.failures + 1
  io.write(string.format('FAIL %s: %s\n', harness.current, msg))
end

function harness.eq(got, want, what)
  harness.checks = harness.checks + 1
  if got ~= want then
    fail(string.format('%s: got %s, want %s', what or 'value', tostring(got), tostring(want)))
  end
end

function harness.ok(cond, what)
  harness.checks = harness.checks + 1
  if not cond then fail(what or 'expected true') end
end

function harness.is_nil(got, what)
  harness.checks = harness.checks + 1
  if got ~= nil then
    fail(string.format('%s: got %s, want nil', what or 'value', tostring(got)))
  end
end

function harness.report(suite)
  if harness.failures == 0 then
    io.write(string.format('ok   %s (%d checks)\n', suite, harness.checks))
    return 0
  end
  io.write(string.format('FAIL %s (%d failures / %d checks)\n', suite, harness.failures, harness.checks))
  return 1
end

return harness
