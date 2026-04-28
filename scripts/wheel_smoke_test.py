"""Post-build smoke test for tethered wheels.

Runs in the cibuildwheel test stage after each wheel is built.  Verifies:

1. ``tethered.pth`` was installed at the top of site-packages.
2. The C guardian extension imports cleanly and is inactive at startup.
3. The auto-activation chain works end-to-end: a child interpreter started
   with ``_TETHERED_CHILD_POLICY`` set runs ``tethered._autoactivate`` via
   the ``.pth``, the inherited policy activates, and an outbound DNS lookup
   for a non-allowed host raises ``EgressBlocked``.

A failure here means the published wheel is broken in a way that the unit
test suite (which runs on the source tree, not the built wheel) cannot
catch — typically a regression in ``setup.py``'s ``build_py_with_pth``
that prevents the ``.pth`` from landing in site-packages.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — the smoke test's whole job is to spawn a child interpreter and verify policy inheritance; argv is hard-coded.
import sys
import sysconfig


def main() -> None:
    """Run the wheel smoke checks; raises ``AssertionError`` on failure."""
    purelib = sysconfig.get_path("purelib")
    pth = os.path.join(purelib, "tethered.pth")
    assert os.path.isfile(pth), f"tethered.pth missing at {pth}"  # nosec B101

    from tethered import _guardian

    assert _guardian.is_active() is False, "guardian should not be active at import"  # nosec B101

    # End-to-end: spawn a child with a deny-all policy, attempt egress,
    # expect EgressBlocked in the child's stderr.  Uses example.test
    # (RFC 6761 reserved TLD — guaranteed non-routable).
    env = dict(os.environ)
    env["_TETHERED_CHILD_POLICY"] = json.dumps(
        {
            "global": {
                "allow": [],
                "allow_localhost": False,
                "log_only": False,
                "fail_closed": False,
                "external_subprocess_policy": "allow",
                "locked": False,
            },
            "scopes": [],
        }
    )
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-c",
            "import socket; socket.getaddrinfo('example.test', 80)",
        ],
        capture_output=True,
        env=env,
        timeout=15,
    )
    assert b"EgressBlocked" in result.stderr, (  # nosec B101
        "child did not enforce inherited policy:\n"
        f"  stdout={result.stdout!r}\n"
        f"  stderr={result.stderr!r}"
    )

    print("tethered wheel smoke test: OK")


if __name__ == "__main__":
    main()
