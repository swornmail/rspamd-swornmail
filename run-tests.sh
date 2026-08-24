#!/bin/sh
# Runs the suite under any Lua 5.1+ / LuaJIT. With no local interpreter,
# falls back to a container so the suite is runnable anywhere Docker is.
set -e
cd "$(dirname "$0")"
LUA_PATH_ARG="./lua/?.lua;./test/?.lua;;"

run() {
  for f in test/test_*.lua; do
    LUA_PATH="$LUA_PATH_ARG" "$1" "$f" || exit 1
  done
}

for interp in luajit lua lua5.4 lua5.3 lua5.1; do
  if command -v "$interp" >/dev/null 2>&1; then
    run "$interp"
    exit 0
  fi
done

echo "no local Lua; running in a container"
exec docker run --rm -v "$PWD:/src" -w /src -e LUA_PATH="$LUA_PATH_ARG" \
  akorn/luajit:2.1-alpine sh -c 'for f in test/test_*.lua; do luajit "$f" || exit 1; done'
