"""CSV formula-injection guard shared by every CSV export.

A cell that starts with ``=``, ``+``, ``-``, ``@``, a tab or a carriage
return is evaluated as a formula by spreadsheet applications. ``csv_safe``
prefixes such strings with a single quote so they are shown as text.
"""

from __future__ import annotations

from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """``value`` unchanged unless it is a str starting with a formula prefix."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
