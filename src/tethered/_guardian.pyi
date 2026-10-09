"""Type stub for the C guardian extension."""

def activate(
    core_namespace: dict[str, object],
    config: object,
    token: object,
    snapshot: list[tuple[object, str, int]],
) -> None: ...
def deactivate(token: object, replacement: object = None) -> bool: ...
def is_active() -> bool: ...
def check_token(token: object) -> bool: ...
def verify() -> bool: ...
def resolve(
    host: object,
    port: object,
    family: int,
    socktype: int,
    proto: int,
    flags: int,
) -> list[tuple[int, int, int, str, tuple[str, int]]]: ...
