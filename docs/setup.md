```python
def search(
    searchfor: bytes,
    mappings: Collection[pwndbg.lib.memory.Page] | None = None,
    start: int | None = None,
    end: int | None = None,
    step: int | None = None,
    aligned: int | None = None,
    limit: int | None = None,
    executable: bool = False,
    writable: bool = False,
) -> Generator[int, None, None]:
    pass
```

---------------------


::: pwndbg.search.search
