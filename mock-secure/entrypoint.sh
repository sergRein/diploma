#!/bin/sh
set -eu

cd /app
mkdir -p tmp/pids tmp/cache tmp/sockets log

if ! bundle check >/dev/null 2>&1; then
  bundle install
fi

rm -f tmp/pids/server.pid
exec bundle exec puma -C config/puma.rb
