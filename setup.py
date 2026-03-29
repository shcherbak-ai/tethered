"""Build configuration for the C guardian extension (required)."""

from __future__ import annotations

from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension("tethered._guardian", ["src/tethered/_guardian.c"]),
    ],
)
