"""Core utility helpers shared across PySOAR."""
import json
from typing import Any


def safe_json_loads(value: Any, default: Any = None) -> Any:
    """Safely parse JSON. Returns default on error or if value is None/empty/already-parsed."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value  # Already parsed
    if not isinstance(value, (str, bytes)):
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, ValueError, TypeError):
        return default
