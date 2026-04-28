"""Type stub for the C guardian extension."""

def activate(
    config: object,
    exc_class: type,
    token_id: int,
    snapshot: list[tuple[object, str, bool]],
) -> None: ...
def deactivate(token_id: int) -> None: ...
def is_active() -> bool: ...
def check_token(token_id: int) -> bool: ...
def resolve(
    host: object,
    port: object,
    family: int,
    socktype: int,
    proto: int,
    flags: int,
) -> list[tuple[int, int, int, str, tuple[str, int]]]: ...
