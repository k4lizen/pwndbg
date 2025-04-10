---
hide:
  - navigation
---

```python
def __exit__(self, exc_type, exc_value, traceback) -> None:
    """
    Automatic breakpoint removal.
    """
    self.remove()
```

```python
__exit__(exc_type, exc_value, traceback) -> None
```

::: pwndbg.dbg.StopPoint.__exit__
