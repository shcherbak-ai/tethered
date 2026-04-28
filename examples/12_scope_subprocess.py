"""Scopes propagate to subprocesses — child sees the parent's effective policy.

``tethered.scope()`` is normally a per-context narrowing of the global policy
*within* a Python process.  When a subprocess is launched from inside a
``with scope(allow=[...])`` block, the child also sees the scope: the
subprocess.Popen audit hook injects the active scope chain into the child's
``_TETHERED_CHILD_POLICY`` env value via frame-locals mutation in
``subprocess.Popen._execute_child``.  The child's ``_autoactivate`` reads
the nested payload, calls ``activate()`` with the parent's global, and
pushes the inherited scopes onto its per-context scope stack.

Result: ``with tethered.scope(allow=[narrow]): subprocess.run(...)`` makes the
child enforce ``global ∩ narrow`` — the same effective policy the parent has
at the launch site.  Race-free across threads.  Works without ``activate()``
too (a library can use ``scope()`` alone for self-defense).

Usage:
    uv run python examples/12_scope_subprocess.py
"""

from __future__ import annotations

import subprocess  # nosec B404
import sys

import tethered

# Parent allows all of api.github.com plus example.com.
tethered.activate(allow=["api.github.com", "*.example.com"])

# Inside this scope, the parent's effective policy is narrowed to api.github.com only.
# A child launched here inherits both the global allow list AND the active scope.
print("Launching child from inside scope(allow=['api.github.com'])...")
with tethered.scope(allow=["api.github.com"]):
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-c",
            (
                "import socket\n"
                "# Allowed by both global AND scope:\n"
                "socket.getaddrinfo('api.github.com', 443)\n"
                "print('Child: api.github.com allowed')\n"
                "# Allowed by global, blocked by inherited scope:\n"
                "try:\n"
                "    socket.getaddrinfo('www.example.com', 80)\n"
                "    print('Child: www.example.com allowed (unexpected)')\n"
                "except Exception as e:\n"
                "    print(f'Child: www.example.com blocked — {type(e).__name__}')"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
print(result.stdout)

# Outside the scope, the same kind of child sees only the global policy.
print("Launching child OUTSIDE the scope...")
result = subprocess.run(  # nosec B603
    [
        sys.executable,
        "-c",
        (
            "import socket\n"
            "socket.getaddrinfo('www.example.com', 80)\n"
            "print('Child: www.example.com allowed (no scope inherited)')"
        ),
    ],
    capture_output=True,
    text=True,
    timeout=15,
)
print(result.stdout)


# Same propagation works via the decorator form — convenient when a
# library function is the natural unit of narrowing.
@tethered.scope(allow=["api.github.com"])
def fetch_via_child() -> str:
    """Run a child interpreter under the scope's narrowed policy."""
    r = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-c",
            (
                "import socket\n"
                "socket.getaddrinfo('api.github.com', 443)\n"
                "print('Child (via @scope): api.github.com allowed')\n"
                "try:\n"
                "    socket.getaddrinfo('www.example.com', 80)\n"
                "    print('Child (via @scope): www.example.com allowed (unexpected)')\n"
                "except Exception as e:\n"
                "    print(f'Child (via @scope): www.example.com blocked — {type(e).__name__}')"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return r.stdout


print("Launching child from a function decorated with @scope(allow=['api.github.com'])...")
print(fetch_via_child())
