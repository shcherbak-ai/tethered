"""Run while an image is built: is tethered installed the way a user would have it?

Fails the build unless ``tethered.pth`` is in site-packages (without it no
child process inherits a policy) and the C extension imports (without it there
is no locked mode).
"""

from __future__ import annotations

import os
import sys
import sysconfig


def main() -> int:
    """Check the installation and say what was found."""
    import tethered
    import tethered._guardian as guardian

    site_packages = sysconfig.get_paths()["purelib"]
    pth = os.path.join(site_packages, "tethered.pth")
    print(f"tethered {tethered.__version__} at {os.path.dirname(tethered.__file__)}")
    print(f"C extension: {guardian.__file__}")
    print(f"bootstrap: {pth}")
    if not os.path.isfile(pth):
        print("tethered.pth is not in site-packages", file=sys.stderr)
        return 1
    if os.path.dirname(os.path.dirname(tethered.__file__)) != site_packages:
        print("tethered is not installed in site-packages", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
