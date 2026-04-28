"""Subprocess auto-propagation — Python children inherit the parent's policy.

When the parent calls ``tethered.activate()``, the policy is serialized into
``_TETHERED_CHILD_POLICY`` in the environment.  The ``tethered.pth`` file
shipped with the package runs ``tethered._autoactivate`` on every Python
interpreter startup; if it sees the env var, it activates tethered with the
same policy before user code runs.

Result: ``multiprocessing.Pool``, ``ProcessPoolExecutor``, gunicorn workers,
or plain ``subprocess.run([sys.executable, ...])`` all auto-inherit the
policy.  No special wrapper required.

Usage:
    uv run python examples/11_subprocess_control.py
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys

import tethered

# Activate the parent's policy.  This populates _TETHERED_CHILD_POLICY in
# os.environ, which child processes inherit by default.
tethered.activate(allow=["api.github.com"])

# Plain subprocess.run — the child auto-activates tethered via tethered.pth.
print("Launching plain subprocess child (no special wrapper)...")
result = subprocess.run(  # nosec B603
    [
        sys.executable,
        "-c",
        (
            "import socket, tethered._core as c\n"
            "print(f'Child: tethered active = {c._config is not None}')\n"
            "socket.getaddrinfo('api.github.com', 443)\n"
            "print('Child: api.github.com allowed')\n"
            "try:\n"
            "    socket.getaddrinfo('evil.test', 80)\n"
            "    print('Child: evil.test allowed (unexpected)')\n"
            "except Exception as e:\n"
            "    print(f'Child: evil.test blocked — {type(e).__name__}')"
        ),
    ],
    capture_output=True,
    text=True,
    timeout=15,
)
print(result.stdout)

# Optional: block "external" subprocess launches — non-Python tools, different
# Python interpreters, or sys.executable launched with site-bypass flags.
# Regular Python children of sys.executable are auto-inheriting and remain
# allowed; this is for the cases auto-inherit can't reach.
print("Re-activating with external_subprocess_policy='block'...")
tethered.activate(allow=["api.github.com"], external_subprocess_policy="block")

# Regular Python child still works (auto-inheriting):
result = subprocess.run(  # nosec B603
    [sys.executable, "-c", "print('regular Python child still allowed')"],
    capture_output=True,
    text=True,
    timeout=10,
)
print(result.stdout.strip())

# Non-Python launch (os.system → /bin/sh or cmd.exe) is now blocked:
try:
    os.system("echo this won't run")  # nosec B605 B607
    print("os.system: allowed (unexpected)")
except tethered.SubprocessBlocked as e:
    print(f"Non-Python launch blocked: {e}")

# sys.executable + site-bypass flag is also blocked (auto-inherit can't reach):
try:
    subprocess.run(  # nosec B603
        [sys.executable, "-S", "-c", "pass"],
        timeout=5,
    )
    print("-S launch: allowed (unexpected)")
except tethered.SubprocessBlocked as e:
    print(f"-S launch blocked: {e}")
