"""Which functions a compiled extension module asks the C library for.

``undefined_symbols(path)`` reads the dynamic symbol table of an ELF shared
object and returns the names it leaves for other libraries to define.  A
module that imports ``connect`` or ``getaddrinfo`` can reach the network
below Python's ``socket`` module, where no audit event is raised and tethered
sees nothing: that is what uvloop does.  The suite uses this to say which of
the installed extension modules could.

Standard library only; 64-bit little-endian ELF, which is every Linux the
container suites run on.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

#: The C library's ways onto the network: connecting, sending to an address, looking a name up.
NETWORK_FUNCTIONS = frozenset(
    {
        "connect",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "getaddrinfo",
        "getnameinfo",
        "gethostbyname",
        "gethostbyname2",
        "gethostbyname_r",
        "gethostbyname2_r",
        "gethostbyaddr",
        "gethostbyaddr_r",
        "res_query",
        "res_search",
        "res_send",
    }
)

_SHT_DYNSYM = 11
_SECTION = struct.Struct("<IIQQQQIIQQ")
_SYMBOL = struct.Struct("<IBBHQQ")


def undefined_symbols(path: Path) -> set[str]:
    """The names a shared object imports: the undefined entries of its ``.dynsym``."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{path}: not a 64-bit little-endian ELF file")
    section_offset = struct.unpack_from("<Q", data, 0x28)[0]
    entry_size, count = struct.unpack_from("<HH", data, 0x3A)
    if entry_size != _SECTION.size or count == 0:
        raise ValueError(f"{path}: no section headers to read")
    sections = [
        _SECTION.unpack_from(data, section_offset + index * entry_size) for index in range(count)
    ]
    names: set[str] = set()
    for _, kind, _, _, offset, size, link, _, _, symbol_size in sections:
        if kind != _SHT_DYNSYM:
            continue
        strings = sections[link][4]
        for position in range(offset, offset + size, symbol_size or _SYMBOL.size):
            name, _, _, defined_in, _, _ = _SYMBOL.unpack_from(data, position)
            if defined_in == 0 and name:
                end = data.index(b"\0", strings + name)
                names.add(data[strings + name : end].decode("ascii", "replace"))
    return names


def network_functions(path: Path) -> set[str]:
    """The networking functions of the C library that a shared object imports."""
    return undefined_symbols(path) & NETWORK_FUNCTIONS
