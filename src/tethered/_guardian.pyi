"""Type stub for the C guardian extension."""

def activate(
    config: object,
    exc_class: type,
    token: object,
    snapshot: list[tuple[object, str, int]],
) -> None: ...
def deactivate(token: object) -> None: ...
def is_active() -> bool: ...
def check_token(token: object) -> bool: ...
def resolve(
    host: object,
    port: object,
    family: int,
    socktype: int,
    proto: int,
    flags: int,
) -> list[tuple[int, int, int, str, tuple[str, int]]]: ...
