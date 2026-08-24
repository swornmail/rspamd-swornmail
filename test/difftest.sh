#!/bin/sh
# Differential arm entry point: reads cases on stdin, writes verdicts on
# stdout. Used by swornmail-go's recorddiff:
#
#   cd ../swornmail-go && go run ./cmd/recorddiff --arm ../rspamd-swornmail/test/difftest.sh
set -e
DIR=$(cd "$(dirname "$0")/.." && pwd)
for interp in luajit lua lua5.4 lua5.3 lua5.1; do
  if command -v "$interp" >/dev/null 2>&1; then
    exec env LUA_PATH="$DIR/lua/?.lua;;" "$interp" "$DIR/test/difftest.lua"
  fi
done
exec docker run --rm -i -v "$DIR:/src" -w /src -e LUA_PATH="./lua/?.lua;;" \
  akorn/luajit:2.1-alpine luajit test/difftest.lua
