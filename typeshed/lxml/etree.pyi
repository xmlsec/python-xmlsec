from typing import Any

def __getattr__(name: str) -> Any: ...  # incomplete

class _Element:
    def __getattr__(self, name: str) -> Any: ...  # incomplete
