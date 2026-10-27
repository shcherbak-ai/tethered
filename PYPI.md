# tethered

Runtime network egress control for Python. One function call sets an allow list for the process, and every connection made through Python's socket layer is checked against it, from inside the process, before the connection is opened. No runtime dependencies and no infrastructure changes.

```bash
uv add tethered
```

Or `pip install tethered`. Python 3.11+ on Linux, macOS and Windows. Wheels are prebuilt; a source install needs a C compiler.

```python
import tethered

tethered.activate(allow=["*.stripe.com", "db.internal"])

import urllib.request
urllib.request.urlopen("https://api.stripe.com/v1/charges")  # allowed: matches *.stripe.com
urllib.request.urlopen("https://evil.test/exfil")            # raises tethered.EgressBlocked
```

- `activate()` sets the ceiling for the whole process. `scope()` narrows a single code path, as a decorator or a `with` block, and never widens the policy.
- Python child processes started with the same interpreter inherit the policy as they start. Every other launch is logged by default and refused with `external_subprocess_policy="block"`.
- With `locked=True`, replacing or switching off the policy takes a token, and monkey-patching tethered's functions or classes, or swapping its active policy, is detected and fails closed.
- It is a guardrail at Python's audit-event layer, not a sandbox. Code that goes below that layer is not stopped: `ctypes`, `cffi`, a C extension, or a library that resolves and connects inside its own C code. Under asyncio it enforces on asyncio's own selector event loop: it will not enforce a policy next to uvloop, and on Windows the default `ProactorEventLoop` gets DNS-time hostname checks only. On a free-threaded build of Python, activating a policy turns the GIL back on.
- The application turns it on. A library uses tethered in its tests and leaves the policy to the application that runs the process.

Upgrading from 0.5.x? 1.0 refuses to run where 0.5.x went on without enforcing, so a deployment can stop at start-up after the upgrade. Read the [migration guide](https://tethered.shcherbak.ai/migrating-to-v1/) first.

The [documentation](https://tethered.shcherbak.ai/) has the quick start, what each server and task queue needs, and the API. The [security model](https://tethered.shcherbak.ai/security/) says what tethered does and does not protect against. The source is in the [repository](https://github.com/shcherbak-ai/tethered#readme).

Licensed under [MIT](https://github.com/shcherbak-ai/tethered/blob/main/LICENSE).
