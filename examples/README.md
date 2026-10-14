# Examples

[← Back to README](../README.md)

Twelve scripts, one for each feature. Each runs on its own and makes real requests to `api.github.com`, so it needs a network connection. From a checkout of the repository:

```bash
uv sync
uv run python examples/01_basic_activate.py
```

| Example | What it shows |
|---|---|
| [01_basic_activate.py](01_basic_activate.py) | A process-wide allow list with `activate()` |
| [02_scope_context_manager.py](02_scope_context_manager.py) | `scope()` as a context manager |
| [03_scope_decorator.py](03_scope_decorator.py) | `scope()` as a function decorator |
| [04_global_with_scope.py](04_global_with_scope.py) | A global policy with a scope: a connection must be allowed by both |
| [05_global_with_nested_scopes.py](05_global_with_nested_scopes.py) | A global policy with nested scopes: each level narrows further |
| [06_locked_mode.py](06_locked_mode.py) | `locked=True`: a policy that needs its token to be replaced, with tamper detection |
| [07_log_only.py](07_log_only.py) | Log-only mode with an `on_blocked` callback: report without blocking |
| [08_scope_in_threads.py](08_scope_in_threads.py) | A scope inside the workers of a thread pool |
| [09_async_scope.py](09_async_scope.py) | `scope()` on async functions, as a decorator and as a context manager |
| [10_package_maintainer.py](10_package_maintainer.py) | A library that finds the hosts it contacts with a log-only scope and publishes them, and an application that puts them into its policy |
| [11_subprocess_control.py](11_subprocess_control.py) | Python child processes inheriting the policy, and `external_subprocess_policy` |
| [12_scope_subprocess.py](12_scope_subprocess.py) | A scope reaching a child process launched inside it |

Examples 11 and 12 start Python children that inherit the policy, which needs tethered installed in site-packages. A development checkout holds an editable install, where a child does not inherit ([why](../docs/SUBPROCESS.md)); `uv run pytest tests_examples/ -v` runs all twelve with the startup hook in place.
