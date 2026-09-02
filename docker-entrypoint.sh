#!/bin/sh
set -eu

# The /data volume is mounted by the container runtime and may initially be
# owned by root. The application runs as the unprivileged "forensix" user, so
# ensure the runtime user can create the database and evidence files.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    chown -R forensix:forensix /data
    exec setpriv --reuid=10001 --regid=10001 --clear-groups "$@"
fi

exec "$@"
