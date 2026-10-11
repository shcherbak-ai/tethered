"""A launcher script: activate the policy first, then import waitress and serve.

The other arrangement of the suite is ``waitress-serve probe_wsgi:application``,
where waitress is running before the application module, and with it the
policy, is imported.  Here the policy is in place before anything of the
server exists; the application module then asks for the same policy again.
"""

from __future__ import annotations

import os

import probe_common


def main() -> None:
    """Activate as ``TETH_ACTIVATE`` says, then serve ``probe_wsgi`` on four threads."""
    probe_common.activate_from_env()

    import probe_wsgi
    from waitress import serve

    serve(probe_wsgi.application, listen=f"127.0.0.1:{os.environ['PORT']}", threads=4)


if __name__ == "__main__":
    main()
