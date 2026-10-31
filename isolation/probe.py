"""Self-authored containment harness. Never loaded from an analyzed artifact."""

import errno
import json
import os
import socket
import subprocess
import sys

case = sys.argv[1]
if case == "filesystem":
    forbidden = [
        "/data/bytasm.sqlite3",
        "/root/.ssh/id_rsa",
        "/var/run/docker.sock",
        "/Users",
        "/home",
        "/app/.git",
        "/app/backend/src/bytasm/api/app.py",
    ]
    # /home can exist as an empty image directory. Nothing from host is mounted.
    if len(sys.argv) > 2:
        forbidden.append(sys.argv[2])
    reads = {}
    for path in forbidden:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            try:
                os.read(fd, 64)
                reads[path] = True
            finally:
                os.close(fd)
        except OSError:
            reads[path] = False
    writes = {}
    for path in ("/data/bytasm-canary", "/root/canary", "/app/canary"):
        try:
            with open(path, "w") as f:
                f.write("canary")
            writes[path] = True
        except OSError:
            writes[path] = False
    print(json.dumps({"reads": reads, "writes": writes, "uid": os.getuid()}))
elif case == "network":
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(("1.1.1.1", 443))
        print("unexpected connection")
        sys.exit(1)
    except OSError:
        print("network denied")
elif case == "disk":
    try:
        with open("/work/fill", "wb") as f:
            for _ in range(32):
                f.write(b"x" * 1024 * 1024)
        sys.exit(1)
    except OSError as exc:
        if exc.errno != errno.ENOSPC:
            raise
        print("disk bounded")
elif case == "pids":
    children = []
    try:
        for _ in range(64):
            children.append(
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
                )
            )
        sys.exit(1)
    except OSError:
        print("pids bounded")
    finally:
        for child in children:
            child.kill()
            child.wait()
elif case == "detach":
    subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("detached child started")
elif case == "timeout":
    while True:
        pass
elif case == "memory":
    allocation = bytearray(768 * 1024 * 1024)
    print(len(allocation))
elif case == "output":
    for _ in range(1024):
        sys.stdout.write("x" * 65536)
elif case == "malformed":
    print('{"invalid":')
elif case == "crash":
    os._exit(9)
