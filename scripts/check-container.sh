#!/bin/sh
# Check the running Compose container really has the settings compose.yaml
# asks for (run after `make compose-up`). `make compose-check` checks the
# configuration; this checks what the kernel applied. It only runs `sh`,
# `grep`, `cat` and `touch` inside the container; no fixture is executed.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

docker compose exec -T api sh -eu -c '
  fail() { echo "FAIL $*"; exit 1; }
  [ "$(id -u)" != 0 ] || fail "runs as root"
  for field in CapPrm CapEff CapBnd CapAmb; do
    grep -q "^$field:[[:space:]]*0000000000000000$" /proc/1/status || fail "$field is not empty"
  done
  grep -q "^NoNewPrivs:[[:space:]]*1$" /proc/1/status || fail "no-new-privileges is off"
  grep -q "^Seccomp:[[:space:]]*2$" /proc/1/status || fail "seccomp filter is not active"
  [ "$(cat /proc/1/comm)" != python ] || fail "PID 1 is the server, not an init process"
  if touch /app/.write-test 2>/dev/null; then fail "root filesystem is writable"; fi
  grep -q " /tmp tmpfs [^ ]*noexec" /proc/mounts || fail "/tmp is not a noexec tmpfs"
  [ "$(cat /sys/fs/cgroup/pids.max)" != max ] || fail "no pids limit"
  [ "$(cat /sys/fs/cgroup/memory.max)" != max ] || fail "no memory limit"
  case "$(cat /sys/fs/cgroup/cpu.max)" in max*) fail "no CPU limit" ;; esac
  [ ! -e /var/run/docker.sock ] || fail "Docker socket is mounted"
  echo "container OK: uid $(id -u), no capabilities, no-new-privileges, seccomp, read-only root,"
  echo "  pids.max $(cat /sys/fs/cgroup/pids.max), memory.max $(cat /sys/fs/cgroup/memory.max), cpu.max $(cat /sys/fs/cgroup/cpu.max)"
'

# Published on the host loopback only.
ports=$(docker compose port api 8000)
case "$ports" in
  127.0.0.1:*) echo "port: $ports" ;;
  *) echo "FAIL port published on $ports"; exit 1 ;;
esac
