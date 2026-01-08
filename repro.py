from __future__ import annotations

import pwndbg


def myfunc() -> None:
    if pwndbg.dbg.is_gdblib_available():
        import pwndbg.gdblib.functions
        _ = pwndbg.gdblib.functions.functions
        print("yes!")
    else:
        print("no!")

myfunc()
