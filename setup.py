"""Build configuration for the C guardian extension and the auto-activation .pth.

The C extension provides tamper-resistant locked mode (built unconditionally).

The .pth file ships at the top level of the wheel — sibling to the ``tethered/``
package directory — so it lands directly in site-packages on install and is
processed by ``site.py`` on every Python interpreter startup.  This is the same
mechanism coverage.py uses for its ``a1_coverage.pth``.  Setuptools'
``data_files`` / ``[tool.setuptools.data-files]`` map to the wheel's ``data/``
subscheme which is ``sys.prefix``, NOT site-packages, so we inject the .pth
into ``build_lib`` via a custom ``build_py`` command instead.
"""

from __future__ import annotations

import os
import shutil

from setuptools import Extension, setup
from setuptools.command.build_py import build_py


class build_py_with_pth(build_py):
    """Copy ``src/tethered.pth`` to the top of ``build_lib``.

    Result: the wheel contains ``tethered.pth`` as a top-level file (sibling
    to the ``tethered/`` package), which pip installs directly into
    site-packages where ``site.py`` will process it on interpreter startup.
    """

    def run(self) -> None:
        super().run()
        src = os.path.join("src", "tethered.pth")
        if os.path.exists(src):
            os.makedirs(self.build_lib, exist_ok=True)
            shutil.copy(src, os.path.join(self.build_lib, "tethered.pth"))


setup(
    ext_modules=[
        Extension("tethered._guardian", ["src/tethered/_guardian.c"]),
    ],
    cmdclass={"build_py": build_py_with_pth},
)
