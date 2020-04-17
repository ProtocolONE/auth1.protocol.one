#!/usr/bin/env sh

exec /app/auth1 migration && /app/auth1 server --registry=mdns