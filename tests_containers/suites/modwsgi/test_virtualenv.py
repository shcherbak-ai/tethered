"""Apache with mod_wsgi and a virtual environment: ``python-home`` and ``python-path``.

mod_wsgi is built for one Python installation, and the packages of an
application usually live in a virtual environment of that Python.  There are
two ways to tell a daemon process about it, and tethered works fully with one
of them only:

- ``python-home=<venv>`` makes the virtual environment the home of the
  embedded Python.  Its site-packages is a site directory from the start, so
  ``tethered.pth`` is processed whenever an interpreter starts, and
  ``sys.executable`` is the Python of the virtual environment.
- ``python-path=<venv>/lib/pythonX.Y/site-packages`` leaves the system Python
  in place and adds the directory with ``site.addsitedir()`` after each
  interpreter has started.  tethered can be imported, and a policy holds in
  the interpreter that activates it.  But the bootstrap in ``tethered.pth``
  runs too late for a second interpreter to join a lock, and
  ``sys.executable`` is the system Python, which knows nothing of tethered:
  a Python child process starts with no policy at all.

Here tethered is installed in the virtual environment only (the fixture
``venv_with_tethered``), as it is in such a deployment.
"""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING, Any

from apache import Site, ask, standing
from expect import (
    AT_FORBIDDEN,
    OUTSIDE_THE_LOCK,
    SUBPROCESS_BLOCKED,
    TETHERED_LOCKED,
    enforces,
    has_no_network,
    reached,
    refused,
)
from harness import FORBIDDEN_NAME, OTHER_PORT, Server, arrivals, reset_arrivals

if TYPE_CHECKING:
    from pathlib import Path

#: Two application groups in one daemon process; the shop gets the first request.
TWO_GROUPS = """
    WSGIRestrictEmbedded On
    WSGIDaemonProcess apps processes=1 threads=4 {option}
    WSGIScriptAlias /shop {shop}
    <Location /shop>
        WSGIProcessGroup apps
        WSGIApplicationGroup shop
    </Location>
    WSGIScriptAlias /blog {blog}
    <Location /blog>
        WSGIProcessGroup apps
        WSGIApplicationGroup blog
    </Location>
"""


def site_packages(venv: Path) -> Path:
    return (
        venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    )


def start(option: str, **shop: Any) -> tuple[Server, dict[str, Any], dict[str, Any]]:
    """Start both applications with a locked policy; returns the server and who they are."""
    site = Site()
    scripts = {
        "shop": site.script("shop", activate="locked", **shop),
        "blog": site.script("blog", activate="locked", **shop),
    }
    server = site.start(TWO_GROUPS.format(option=option, **scripts))
    return server, ask(server, "/shop", "whoami"), ask(server, "/blog", "whoami")


def test_tethered_is_in_the_virtual_environment_only(venv_with_tethered: Path) -> None:
    # What the tests below rest on.
    for python, expected in ((sys.executable, 1), (str(venv_with_tethered / "bin" / "python"), 0)):
        done = subprocess.run([python, "-c", "import tethered"], capture_output=True, check=False)
        assert done.returncode == expected, (python, done.stderr)
    assert (site_packages(venv_with_tethered) / "tethered.pth").is_file()


def test_python_home_gives_every_interpreter_and_every_child_the_policy(
    venv_with_tethered: Path,
) -> None:
    server, shop, blog = start(f"python-home={venv_with_tethered}")
    for me in (shop, blog):
        assert me["prefix"] == str(venv_with_tethered), me
        assert me["executable"] == str(venv_with_tethered / "bin" / "python"), me
    assert standing(shop) == "holder", shop
    # The second group's interpreter joined the lock as it started.
    assert standing(blog) == "joined", blog
    assert blog["at_startup"]["locked"] is True, blog
    for mount in ("/shop", "/blog"):
        enforces(server, mount)
        report = ask(server, mount, "child", FORBIDDEN_NAME, OTHER_PORT)
        reached(report)
        assert report["child"]["executable"] == str(venv_with_tethered / "bin" / "python")
        assert report["child"]["locked"] is True, report
        refused(report["child"])
    assert "tethered.pth not found" not in server.log


def test_python_path_leaves_children_and_other_interpreters_without_the_policy(
    venv_with_tethered: Path,
) -> None:
    """Limit: with ``python-path`` only the interpreter that activates is covered.

    Three things differ from ``python-home``, and tethered logs the first two:

    - ``tethered.pth`` is in no directory that ``site.py`` processed at
      startup ("tethered.pth not found");
    - a second application group cannot join the lock, because mod_wsgi adds
      the directory, and with it the bootstrap, after the interpreter's
      startup is over.  It is outside the lock: no network, and its own
      ``activate()`` is refused;
    - a Python child of the lock holder is the system Python, has no
      tethered and reaches the forbidden destination.  tethered treats the
      launch as external and warns; ``external_subprocess_policy="block"``
      refuses it (next test).
    """
    server, shop, blog = start(f"python-path={site_packages(venv_with_tethered)}")
    for me in (shop, blog):
        assert me["prefix"] == sys.base_prefix, me
        assert me["executable"].startswith(sys.base_prefix), me

    assert standing(shop) == "holder", shop
    enforces(server, "/shop")
    server.wait_log("tethered: tethered.pth not found")

    assert blog["activation"]["exception"] == TETHERED_LOCKED, blog
    assert OUTSIDE_THE_LOCK in blog["activation"]["message"], blog
    assert blog["locked"] is False, blog
    has_no_network(server, "/blog")
    server.wait_log("this interpreter could not join the locked policy of its process")
    server.wait_log(
        "a policy can only be joined once, while an interpreter starts, "
        "and this interpreter's startup is over"
    )

    reset_arrivals()
    report = ask(server, "/shop", "child", FORBIDDEN_NAME, OTHER_PORT)
    reached(report)
    child = report["child"]
    assert child["tethered_imported"] is False, report
    assert child["executable"].startswith(sys.base_prefix), report
    reached(child)
    assert arrivals() == {AT_FORBIDDEN: 1}
    server.wait_log(r"external subprocess launch detected: subprocess\.Popen\(")


def test_python_path_with_block_refuses_the_child_that_would_have_no_policy(
    venv_with_tethered: Path,
) -> None:
    server, shop, _blog = start(f"python-path={site_packages(venv_with_tethered)}", esp="block")
    assert standing(shop) == "holder", shop
    report = ask(server, "/shop", "child", FORBIDDEN_NAME, OTHER_PORT)
    refused(report, SUBPROCESS_BLOCKED)
    assert arrivals() == {}
